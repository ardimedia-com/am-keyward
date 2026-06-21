using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Domain.Audit;

namespace Am.Keyward.Infrastructure.Persistence;

/// <summary>
/// Per-tenant hash-chained audit sink. It stages an <see cref="AuditEntry"/> on the shared
/// <see cref="KeywardDbContext"/> (persisted by the caller's SaveChanges). The chain position (sequence)
/// and hashes are assigned at commit by <see cref="AuditChainInterceptor"/> under a per-chain lock — the
/// single writer — so concurrent appends cannot fork the chain or collide on a sequence number.
/// </summary>
public sealed class DbAuditSink(KeywardDbContext db, IClock clock) : IAuditSink
{
    public ValueTask AppendAsync(AuditRequest request, CancellationToken ct = default)
    {
        // Sequence + previous/current hash are filled in by AuditChainInterceptor at SaveChanges.
        db.AuditEntries.Add(new AuditEntry(
            Guid.NewGuid(), request.TenantId, sequence: 0, request.Action, request.ResourceType,
            request.ResourceId, request.ActorPseudonymId, clock.UtcNow, AuditChainHash.GenesisHash, hash: string.Empty));
        return ValueTask.CompletedTask;
    }
}
