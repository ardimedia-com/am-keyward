using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Domain.Audit;
using Microsoft.EntityFrameworkCore;

namespace Am.Keyward.Infrastructure.Persistence;

/// <summary>
/// Minimal per-tenant hash-chained audit sink: it adds an <see cref="AuditEntry"/> to the shared
/// <see cref="KeywardDbContext"/> (persisted by the caller's SaveChanges). The hardened version
/// (DB SEQUENCE ordering, single-writer serialization, exported chain-head checkpoint) lands in the
/// ops-hardening slice; the on-the-wire chain shape (SHA-256 over the canonical fields + previous hash)
/// is already in place here.
/// </summary>
public sealed class DbAuditSink(KeywardDbContext db, IClock clock) : IAuditSink
{
    public async ValueTask AppendAsync(AuditRequest request, CancellationToken ct = default)
    {
        var prev = await db.AuditEntries
            .Where(a => a.TenantId == request.TenantId)
            .OrderByDescending(a => a.Sequence)
            .Select(a => new { a.Sequence, a.Hash })
            .FirstOrDefaultAsync(ct)
            .ConfigureAwait(false);

        var sequence = (prev?.Sequence ?? 0) + 1;
        var previousHash = prev?.Hash ?? AuditChainHash.GenesisHash;
        var occurredAt = clock.UtcNow;
        var hash = AuditChainHash.Compute(
            request.TenantId, sequence, request.Action, request.ResourceType,
            request.ResourceId, request.ActorPseudonymId, occurredAt, previousHash);

        db.AuditEntries.Add(new AuditEntry(
            Guid.NewGuid(), request.TenantId, sequence, request.Action, request.ResourceType,
            request.ResourceId, request.ActorPseudonymId, occurredAt, previousHash, hash));
    }
}
