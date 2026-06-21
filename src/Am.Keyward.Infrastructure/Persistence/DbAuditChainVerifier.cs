using Am.Keyward.Core.Abstractions;
using Microsoft.EntityFrameworkCore;

namespace Am.Keyward.Infrastructure.Persistence;

/// <summary>
/// Verifies a tenant's audit hash chain: walks the entries in sequence order, recomputing each link's hash
/// from its fields plus the previous link's hash, and reports the first sequence where the recomputed hash
/// differs (tampering), the chain links to the wrong previous hash, or a sequence number is missing.
/// Reads through the tenant query filter, so the caller must run in the tenant's scope.
/// </summary>
public sealed class DbAuditChainVerifier(KeywardDbContext db) : IAuditChainVerifier
{
    public async Task<AuditChainStatus> VerifyAsync(Guid? tenantId, CancellationToken ct = default)
    {
        var entries = await db.AuditEntries
            .Where(a => a.TenantId == tenantId)
            .OrderBy(a => a.Sequence)
            .ToListAsync(ct)
            .ConfigureAwait(false);

        var previousHash = AuditChainHash.GenesisHash;
        long expectedSequence = 1;

        foreach (var entry in entries)
        {
            if (entry.Sequence != expectedSequence)
            {
                return new AuditChainStatus(false, expectedSequence - 1, entry.Sequence,
                    $"Sequence gap: expected {expectedSequence}, found {entry.Sequence}.");
            }

            if (entry.PreviousHash != previousHash)
            {
                return new AuditChainStatus(false, entry.Sequence - 1, entry.Sequence,
                    "Previous-hash link does not match the prior entry.");
            }

            var expectedHash = AuditChainHash.Compute(
                entry.TenantId, entry.Sequence, entry.Action, entry.ResourceType,
                entry.ResourceId, entry.ActorPseudonymId, entry.OccurredAt, entry.PreviousHash);

            if (entry.Hash != expectedHash)
            {
                return new AuditChainStatus(false, entry.Sequence - 1, entry.Sequence,
                    "Recomputed hash does not match the stored hash (entry was altered).");
            }

            previousHash = entry.Hash;
            expectedSequence++;
        }

        return new AuditChainStatus(true, entries.Count, null, null);
    }
}
