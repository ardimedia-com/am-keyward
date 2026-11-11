using Am.Keyward.Core.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Am.Keyward.Infrastructure.Crypto;

/// <summary>Outcome of the key-ownership check (see <see cref="KekCanaryService"/>).</summary>
public enum KekIntegrityStatus
{
    /// <summary>The check has not run yet, or could not run (database unreachable).</summary>
    Unknown = 0,

    /// <summary>The key this process holds unwrapped the canary — it owns this data.</summary>
    Ok = 1,

    /// <summary>There was no canary; this installation wrote it. A fresh database, or the first start after the upgrade.</summary>
    Created = 2,

    /// <summary>
    /// This key cannot open the canary, or — when there was no canary yet — cannot open the values the database
    /// already holds. The data belongs to a DIFFERENT key.
    /// </summary>
    Conflict = 3,
}

/// <summary>What to do when the key does not own the data.</summary>
public enum KekConflictBehaviour
{
    /// <summary>Refuse to encrypt or decrypt (default). Keyward degrades to unavailable; nothing else is affected.</summary>
    Disable = 0,

    /// <summary>Log and carry on. For a deliberate migration window only — every value written meanwhile is unreadable to the other installation.</summary>
    Warn = 1,
}

public sealed class KeywardKeyIntegrityOptions
{
    public const string SectionName = "Keyward:KeyIntegrity";

    /// <summary>
    /// Default <see cref="KekConflictBehaviour.Disable"/>: on a conflict, continuing to write is the one
    /// action that makes the situation strictly worse — every new value is sealed under a key the other
    /// installation does not have, so the split grows with every save. Refusing keeps the damage at zero and
    /// makes the cause visible immediately.
    /// </summary>
    public KekConflictBehaviour OnConflict { get; set; } = KekConflictBehaviour.Disable;

    /// <summary>
    /// Where this host keeps its key, published into the installation registry for diagnosis only — the
    /// library never reads a path. Worth setting where two installations may share a database: seeing that
    /// both name the same directory is what turns "they happen to agree" into "they are configured to".
    /// </summary>
    public string? KeyCustodyLocation { get; set; }

    /// <summary>
    /// How long an installation counts as still running after its last start. A deployment that was
    /// decommissioned must stop raising questions, so its row ages out of the comparison instead of being
    /// deleted (the history stays readable on the status page).
    /// </summary>
    public int PeerStaleAfterDays { get; set; } = 30;
}

/// <summary>
/// Raised instead of encrypting or decrypting with a key that does not own the stored data.
/// </summary>
public sealed class KeywardKeyMismatchException(string message) : InvalidOperationException(message);

/// <summary>
/// The installation-wide verdict of the key-ownership check, consulted by the crypto path. Singleton: written at
/// startup (<see cref="KekIntegrityStartupCheck"/>) and re-evaluated by <see cref="RecheckAsync"/> afterwards.
///
/// <para><b>Re-evaluation.</b> A verdict is not taken once and for all:</para>
/// <list type="bullet">
/// <item>An <see cref="KekIntegrityStatus.Unknown"/> verdict (the database was unreachable at start) is re-run
/// LAZILY on the first protect/unprotect that follows (<see cref="EnsureVerifiedAsync"/>, single-flight, at most
/// once per <see cref="LazyRetryInterval"/>), so a mismatch is caught before the first value is written, not only
/// after the next restart.</item>
/// <item>The ops monitor re-runs it on every pass, and the migration safety net (or anything else that knows the
/// database was swapped under the running app) calls <see cref="RecheckAsync"/> directly: a database replaced by a
/// copy sealed under another key is then blocked instead of being written into.</item>
/// </list>
/// <para>A recheck that cannot reach the database keeps the previous verdict: an availability problem never turns
/// a verified key into an unverified one, and never lifts a confirmed conflict.</para>
/// </summary>
public sealed class KeywardKeyIntegrityState
{
    /// <summary>Minimum pause between two lazy re-runs while the verdict stays <see cref="KekIntegrityStatus.Unknown"/>.</summary>
    public static readonly TimeSpan LazyRetryInterval = TimeSpan.FromSeconds(30);

    /// <summary>Upper bound for one recheck, so a hanging database cannot hold every caller that waits on it.</summary>
    private static readonly TimeSpan RecheckTimeout = TimeSpan.FromSeconds(30);

    private readonly IOptions<KeywardKeyIntegrityOptions> _options;
    private readonly IServiceScopeFactory? _scopeFactory;
    private readonly IClock? _clock;
    private readonly ILogger? _logger;
    private readonly Lock _gate = new();
    private Task<KekIntegrityStatus>? _inFlight;
    private DateTimeOffset _lastAttempt = DateTimeOffset.MinValue;
    private volatile bool _attempted;

    /// <summary>A verdict holder without the ability to recheck (unit tests, hosts that wire the crypto path by hand).</summary>
    public KeywardKeyIntegrityState(IOptions<KeywardKeyIntegrityOptions> options)
    {
        _options = options;
    }

    /// <summary>The DI constructor: the state can re-run the canary itself (<see cref="RecheckAsync"/>).</summary>
    public KeywardKeyIntegrityState(
        IOptions<KeywardKeyIntegrityOptions> options,
        IServiceScopeFactory scopeFactory,
        IClock clock,
        ILogger<KeywardKeyIntegrityState> logger)
    {
        _options = options;
        _scopeFactory = scopeFactory;
        _clock = clock;
        _logger = logger;
    }

    public KekIntegrityStatus Status { get; private set; } = KekIntegrityStatus.Unknown;

    /// <summary>Operator-facing explanation of a conflict (which key ids are involved, when the canary was written).</summary>
    public string? Detail { get; private set; }

    /// <summary>When the current verdict was reached; <c>null</c> before the first check.</summary>
    public DateTimeOffset? CheckedAt { get; private set; }

    public void Record(KekIntegrityStatus status, string? detail = null)
    {
        Status = status;
        Detail = detail;
        CheckedAt = Now;
        _attempted = true;
    }

    /// <summary>
    /// True only for a confirmed conflict under the default behaviour. An <see cref="KekIntegrityStatus.Unknown"/>
    /// verdict deliberately does NOT block: a database that was unreachable at startup is an availability
    /// problem, and turning it into a permanent refusal would take Keyward down for a reason that has nothing
    /// to do with key custody. It is re-evaluated instead (<see cref="EnsureVerifiedAsync"/>).
    /// </summary>
    public bool IsBlocked =>
        Status == KekIntegrityStatus.Conflict && _options.Value.OnConflict == KekConflictBehaviour.Disable;

    public void ThrowIfBlocked()
    {
        if (IsBlocked)
        {
            throw new KeywardKeyMismatchException(
                "The key-encryption key this installation holds does not own the data in this database, so "
                + "encrypting or decrypting would produce values the other installation cannot read. "
                + (Detail ?? string.Empty));
        }
    }

    /// <summary>
    /// Called by the crypto choke point before every protect/unprotect. While the verdict is
    /// <see cref="KekIntegrityStatus.Unknown"/> because a check already ran and could not reach the database, it
    /// re-runs the check (single-flight; at most once per <see cref="LazyRetryInterval"/>). It never throws for an
    /// unreachable database — the caller's own database work reports that; <see cref="ThrowIfBlocked"/> decides.
    /// A state that never ran a check (no hosted startup check, e.g. a unit test) does nothing here.
    /// </summary>
    public async ValueTask EnsureVerifiedAsync(CancellationToken ct = default)
    {
        if (Status != KekIntegrityStatus.Unknown || !_attempted || _scopeFactory is null)
        {
            return;
        }

        Task<KekIntegrityStatus> run;
        lock (_gate)
        {
            if (_inFlight is { IsCompleted: false } running)
            {
                run = running;
            }
            else if (Now - _lastAttempt < LazyRetryInterval)
            {
                return;
            }
            else
            {
                run = _inFlight = RecheckCoreAsync();
            }
        }

        await run.WaitAsync(ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Re-runs the key-ownership check now (single-flight: concurrent callers share one run) and returns the
    /// resulting verdict. The hook for anything that knows the database may have changed under the running app —
    /// the migration safety net after it applied migrations, an operator action, the ops monitor. A run that cannot
    /// reach the database keeps the previous verdict (logged).
    /// </summary>
    /// <exception cref="InvalidOperationException">The state was built without the services it needs to recheck.</exception>
    public async Task<KekIntegrityStatus> RecheckAsync(CancellationToken ct = default)
    {
        if (_scopeFactory is null)
        {
            throw new InvalidOperationException(
                "This key-integrity state was created without a service scope factory and cannot re-run the check.");
        }

        Task<KekIntegrityStatus> run;
        lock (_gate)
        {
            run = _inFlight is { IsCompleted: false } running ? running : _inFlight = RecheckCoreAsync();
        }

        return await run.WaitAsync(ct).ConfigureAwait(false);
    }

    private DateTimeOffset Now => _clock?.UtcNow ?? DateTimeOffset.UtcNow;

    private async Task<KekIntegrityStatus> RecheckCoreAsync()
    {
        // Detached from any single caller's token (several callers may wait on this run), bounded by a timeout.
        // Yield first so the caller leaves the lock before any database work starts.
        await Task.Yield();
        using CancellationTokenSource timeout = new(RecheckTimeout);
        KekIntegrityStatus previous = Status;
        try
        {
            using IServiceScope scope = _scopeFactory!.CreateScope();

            // Trusted, tenant-less maintenance read: the canary's foreign-ciphertext probe must see one stored
            // version across tenants, which row-level security otherwise hides from a scope without a tenant.
            // The scope is this run's own, so the read bypass ends with it.
            scope.ServiceProvider.GetRequiredService<Tenancy.SystemReadScope>().Enabled = true;

            KekCanaryService canary = scope.ServiceProvider.GetRequiredService<KekCanaryService>();
            KeywardInstallationRegistry registry = scope.ServiceProvider.GetRequiredService<KeywardInstallationRegistry>();
            string writtenBy = $"{registry.Current.MachineName} ({registry.Current.EnvironmentName})";

            (KekIntegrityStatus status, string? detail) =
                await canary.VerifyOrCreateAsync(writtenBy, timeout.Token).ConfigureAwait(false);
            Record(status, detail);
            LogVerdict(previous, status, detail);
            return status;
        }
        catch (Exception ex)
        {
            _attempted = true;
            if (previous == KekIntegrityStatus.Unknown)
            {
                Detail = ex.Message;
                _logger?.LogError(ex,
                    "KEYWARD: the key-ownership check could not run - continuing without a verdict. It is retried on "
                    + "the next use of the key and by the ops monitor; a key mismatch is not caught until then.");
            }
            else
            {
                // Keep the verdict: an unreachable database proves nothing about the key.
                _logger?.LogWarning(ex,
                    "KEYWARD: the key-ownership recheck could not run; the previous verdict {Status} stays in force.",
                    previous);
            }

            return Status;
        }
        finally
        {
            lock (_gate)
            {
                _lastAttempt = Now;
            }
        }
    }

    private void LogVerdict(KekIntegrityStatus previous, KekIntegrityStatus status, string? detail)
    {
        if (_logger is null)
        {
            return;
        }

        switch (status)
        {
            case KekIntegrityStatus.Ok when previous != KekIntegrityStatus.Ok:
                _logger.LogInformation("KEYWARD: the key-encryption key owns this database (canary verified).");
                break;

            case KekIntegrityStatus.Created:
                _logger.LogInformation("KEYWARD: key-ownership canary written. {Detail}", detail);
                break;

            case KekIntegrityStatus.Conflict when IsBlocked:
                _logger.LogCritical(
                    "KEYWARD: KEY MISMATCH - encryption and decryption are DISABLED to keep the split from growing. "
                    + "{Detail}", detail);
                break;

            case KekIntegrityStatus.Conflict:
                _logger.LogCritical(
                    "KEYWARD: KEY MISMATCH - configured to continue anyway (Keyward:KeyIntegrity:OnConflict=Warn). "
                    + "Every value written from now on will be unreadable to the installation that owns the data. "
                    + "{Detail}", detail);
                break;
        }
    }
}
