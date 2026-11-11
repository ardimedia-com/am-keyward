using System.Text.Json;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Infrastructure.Auth;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Am.Keyward.Infrastructure.Persistence;

/// <summary>One recorded head of a tenant's audit chain.</summary>
/// <param name="TenantId">The chain's tenant; <c>null</c> for the tenant-less (personal/system) chain.</param>
/// <param name="Sequence">The head's sequence number when it was recorded.</param>
/// <param name="Hash">The head's hash when it was recorded.</param>
/// <param name="At">When it was recorded (UTC).</param>
public sealed record AuditHeadAnchor(Guid? TenantId, long Sequence, string Hash, DateTimeOffset At);

/// <summary>
/// Out-of-band anchors for the audit hash chains. The chain inside the database proves that no entry was altered
/// and none is missing in the middle, but its hash is unkeyed: whoever can write the database can cut entries off
/// the END (or restore an older copy) and the remaining prefix still verifies. The ops monitor therefore writes each
/// chain's verified head — tenant, sequence, hash, time — to an append-only, hash-chained file outside the database
/// (<see cref="BreakGlassOptions.ResolveAuditAnchorFilePath"/>, by default next to the break-glass trail), and the
/// verifier (<see cref="DbAuditChainVerifier"/>) fails when the database's chain is behind, or differs from, the
/// latest recorded anchor.
///
/// <para>Optional: without a configured break-glass or anchor path, or with
/// <see cref="BreakGlassOptions.AuditAnchorsEnabled"/> off, <see cref="IsEnabled"/> is false and nothing is written
/// or checked. After a DELIBERATE restore of an older database the anchors correctly report it; the operator archives
/// the anchor file (see the operations runbook) once the restore is confirmed.</para>
/// </summary>
public sealed class AuditHeadAnchorLog
{
    private readonly HashChainedJsonLinesFile? _file;
    private readonly IClock _clock;
    private readonly ILogger? _logger;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly Dictionary<Guid, AuditHeadAnchor> _latest = [];
    private long _loadedLength = -1;
    private DateTime _loadedWriteTime;

    public AuditHeadAnchorLog(IOptions<BreakGlassOptions> options, IClock clock, ILogger<AuditHeadAnchorLog>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        _clock = clock;
        _logger = logger;
        string? path = options.Value.ResolveAuditAnchorFilePath();
        _file = path is null ? null : new HashChainedJsonLinesFile(path, logger);
    }

    /// <summary>Whether anchors are written and checked.</summary>
    public bool IsEnabled => _file is not null;

    /// <summary>The anchor file, when enabled.</summary>
    public string? FilePath => _file?.Path;

    /// <summary>The latest recorded anchor of <paramref name="tenantId"/>'s chain, or <c>null</c>.</summary>
    public async Task<AuditHeadAnchor?> GetLatestAsync(Guid? tenantId, CancellationToken ct = default)
    {
        if (_file is null)
        {
            return null;
        }

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await this.RefreshAsync(ct).ConfigureAwait(false);
            return _latest.GetValueOrDefault(Key(tenantId));
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Records <paramref name="sequence"/>/<paramref name="hash"/> as the verified head of <paramref name="tenantId"/>'s
    /// chain, unless an anchor at or beyond that sequence is already recorded. Returns whether a line was written.
    /// </summary>
    public async Task<bool> RecordAsync(Guid? tenantId, long sequence, string hash, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(hash);
        if (_file is null || sequence <= 0)
        {
            return false;
        }

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await this.RefreshAsync(ct).ConfigureAwait(false);
            if (_latest.TryGetValue(Key(tenantId), out AuditHeadAnchor? known) && known.Sequence >= sequence)
            {
                return false;
            }

            AuditHeadAnchor anchor = new(tenantId, sequence, hash, _clock.UtcNow);
            await _file.AppendAsync(anchor, ct).ConfigureAwait(false);
            _latest[Key(tenantId)] = anchor;
            this.RememberFileState();
            return true;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Verifies the anchor file's own hash chain; an intact empty result when anchoring is off.</summary>
    public Task<HashChainVerification> VerifyAsync(CancellationToken ct = default) =>
        _file?.VerifyAsync(ct)
        ?? Task.FromResult(new HashChainVerification(true, 0, [], null, HashChainedJsonLinesFile.GenesisHash, null));

    /// <summary>Re-reads the file when it changed since the last read (another instance may append to it too).</summary>
    private async Task RefreshAsync(CancellationToken ct)
    {
        FileInfo info = new(_file!.Path);
        long length = info.Exists ? info.Length : 0;
        DateTime written = info.Exists ? info.LastWriteTimeUtc : default;
        if (length == _loadedLength && written == _loadedWriteTime)
        {
            return;
        }

        _latest.Clear();
        await foreach (JsonElement record in _file.ReadRecordsAsync(ct).ConfigureAwait(false))
        {
            try
            {
                AuditHeadAnchor? anchor = record.Deserialize<AuditHeadAnchor>(JsonSerializerOptions.Web);
                if (anchor is not null
                    && (!_latest.TryGetValue(Key(anchor.TenantId), out AuditHeadAnchor? known) || anchor.Sequence >= known.Sequence))
                {
                    _latest[Key(anchor.TenantId)] = anchor;
                }
            }
            catch (JsonException ex)
            {
                _logger?.LogWarning(ex, "KEYWARD: an audit anchor in {Path} could not be read and was skipped.", _file.Path);
            }
        }

        _loadedLength = length;
        _loadedWriteTime = written;
    }

    private void RememberFileState()
    {
        FileInfo info = new(_file!.Path);
        _loadedLength = info.Exists ? info.Length : 0;
        _loadedWriteTime = info.Exists ? info.LastWriteTimeUtc : default;
    }

    private static Guid Key(Guid? tenantId) => tenantId ?? Guid.Empty;
}
