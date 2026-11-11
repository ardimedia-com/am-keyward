using System.Collections.Concurrent;
using Am.Keyward.Core.Abstractions;
using Microsoft.EntityFrameworkCore;

namespace Am.Keyward.Infrastructure.Persistence;

/// <summary>
/// The last verified position of each tenant's audit chain in this process (sequence + hash), so a periodic
/// verification only has to walk the entries added since. In memory by design: after a restart the first run is a
/// full verification again. Singleton.
/// </summary>
public sealed class AuditChainCheckpoints
{
    private readonly ConcurrentDictionary<Guid, (long Sequence, string Hash)> _verified = new();

    /// <summary>The verified head of <paramref name="tenantId"/>'s chain, when one is known.</summary>
    public bool TryGet(Guid? tenantId, out long sequence, out string hash)
    {
        if (_verified.TryGetValue(Key(tenantId), out var checkpoint))
        {
            (sequence, hash) = checkpoint;
            return true;
        }

        (sequence, hash) = (0, string.Empty);
        return false;
    }

    internal void Set(Guid? tenantId, long sequence, string hash) => _verified[Key(tenantId)] = (sequence, hash);

    internal void Forget(Guid? tenantId) => _verified.TryRemove(Key(tenantId), out _);

    private static Guid Key(Guid? tenantId) => tenantId ?? Guid.Empty;
}

/// <summary>
/// Verifies a tenant's audit hash chain: walks the entries in sequence order, recomputing each link's hash
/// from its fields plus the previous link's hash, and reports the first sequence where the recomputed hash
/// differs (tampering), the chain links to the wrong previous hash, or a sequence number is missing.
/// Reads through the tenant query filter, so the caller must run in the tenant's scope.
///
/// <para><b>Streaming, incremental.</b> Entries are streamed untracked, never loaded as a list. The port method
/// (<see cref="VerifyAsync(Guid?, CancellationToken)"/>) always verifies the whole chain; the ops monitor calls
/// <see cref="VerifyAsync(Guid?, bool, CancellationToken)"/> with <c>full: false</c> on its hourly pass, which starts
/// from the last verified checkpoint (<see cref="AuditChainCheckpoints"/>) after confirming the checkpoint entry still
/// carries the same hash — an entry rewritten before it would have to change that hash too. If the checkpoint no
/// longer matches (a database swapped under the running app), it falls back to a full walk. A full walk runs daily.</para>
///
/// <para><b>Truncation.</b> A prefix of a valid chain is itself valid, so cutting entries off the end leaves nothing
/// for the chain to show. When out-of-band anchors are enabled (<see cref="AuditHeadAnchorLog"/>) the result also fails
/// when the chain is shorter than, or differs at, the latest recorded anchor.</para>
/// </summary>
public sealed class DbAuditChainVerifier(
    IDbContextFactory<KeywardDbContext> dbFactory,
    AuditChainCheckpoints? checkpoints = null,
    AuditHeadAnchorLog? anchors = null) : IAuditChainVerifier
{
    private readonly AuditChainCheckpoints _checkpoints = checkpoints ?? new AuditChainCheckpoints();

    /// <summary>Verifies the whole chain of <paramref name="tenantId"/>.</summary>
    public Task<AuditChainStatus> VerifyAsync(Guid? tenantId, CancellationToken ct = default) =>
        this.VerifyAsync(tenantId, full: true, ct);

    /// <summary>
    /// Verifies <paramref name="tenantId"/>'s chain — from the beginning when <paramref name="full"/>, otherwise from
    /// the last verified checkpoint. <see cref="AuditChainStatus.EntriesChecked"/> is the chain's verified length.
    /// </summary>
    public async Task<AuditChainStatus> VerifyAsync(Guid? tenantId, bool full, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);

        long startAfter = 0;
        var previousHash = AuditChainHash.GenesisHash;
        if (!full && _checkpoints.TryGet(tenantId, out long checkpointSequence, out string checkpointHash))
        {
            var stored = await db.AuditEntries.AsNoTracking()
                .Where(a => a.TenantId == tenantId && a.Sequence == checkpointSequence)
                .Select(a => a.Hash)
                .FirstOrDefaultAsync(ct)
                .ConfigureAwait(false);
            if (string.Equals(stored, checkpointHash, StringComparison.Ordinal))
            {
                startAfter = checkpointSequence;
                previousHash = checkpointHash;
            }
        }

        var entries = db.AuditEntries
            .AsNoTracking()
            .Where(a => a.TenantId == tenantId && a.Sequence > startAfter)
            .OrderBy(a => a.Sequence)
            .AsAsyncEnumerable();

        long expectedSequence = startAfter + 1;
        await foreach (var entry in entries.WithCancellation(ct).ConfigureAwait(false))
        {
            if (entry.Sequence != expectedSequence)
            {
                return this.Broken(tenantId, expectedSequence - 1, entry.Sequence,
                    $"Sequence gap: expected {expectedSequence}, found {entry.Sequence}.");
            }

            if (entry.PreviousHash != previousHash)
            {
                return this.Broken(tenantId, entry.Sequence - 1, entry.Sequence,
                    "Previous-hash link does not match the prior entry.");
            }

            // Each entry is recomputed with the canonical form of ITS hash version, so chains that span the
            // v1 → v2 switch verify end to end.
            string expectedHash;
            try
            {
                expectedHash = AuditChainHash.Compute(entry, entry.Sequence, entry.PreviousHash);
            }
            catch (InvalidOperationException ex)
            {
                return this.Broken(tenantId, entry.Sequence - 1, entry.Sequence, ex.Message);
            }

            if (entry.Hash != expectedHash)
            {
                return this.Broken(tenantId, entry.Sequence - 1, entry.Sequence,
                    "Recomputed hash does not match the stored hash (entry was altered).");
            }

            previousHash = entry.Hash;
            expectedSequence++;
        }

        long head = expectedSequence - 1;
        if (head > 0)
        {
            _checkpoints.Set(tenantId, head, previousHash);
        }

        if (anchors is { IsEnabled: true }
            && await anchors.GetLatestAsync(tenantId, ct).ConfigureAwait(false) is { } anchor)
        {
            if (head < anchor.Sequence)
            {
                return this.Broken(tenantId, head, head + 1,
                    $"The audit chain ends at sequence {head}, but the out-of-band anchor recorded sequence "
                    + $"{anchor.Sequence} at {anchor.At:yyyy-MM-dd HH:mm} UTC: entries were removed from the end, or the "
                    + "database was restored to an older state.");
            }

            string? atAnchor = anchor.Sequence == head
                ? previousHash
                : await db.AuditEntries.AsNoTracking()
                    .Where(a => a.TenantId == tenantId && a.Sequence == anchor.Sequence)
                    .Select(a => a.Hash)
                    .FirstOrDefaultAsync(ct)
                    .ConfigureAwait(false);
            if (!string.Equals(atAnchor, anchor.Hash, StringComparison.Ordinal))
            {
                return this.Broken(tenantId, anchor.Sequence - 1, anchor.Sequence,
                    $"The audit entry at sequence {anchor.Sequence} differs from the out-of-band anchor recorded at "
                    + $"{anchor.At:yyyy-MM-dd HH:mm} UTC: the chain was rewritten from that point on.");
            }
        }

        return new AuditChainStatus(true, head, null, null);
    }

    private AuditChainStatus Broken(Guid? tenantId, long entriesChecked, long firstBroken, string detail)
    {
        // Never resume from a checkpoint of a chain that just failed: the next run walks it again in full.
        _checkpoints.Forget(tenantId);
        return new AuditChainStatus(false, entriesChecked, firstBroken, detail);
    }
}
