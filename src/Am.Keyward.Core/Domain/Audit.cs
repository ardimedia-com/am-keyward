using Am.Keyward.Core.Domain;

namespace Am.Keyward.Core.Domain.Audit;

/// <summary>
/// An append-only audit record, part of a per-tenant tamper-evident hash chain. The actor is stored
/// as an opaque pseudonym (no PII) to support DSGVO crypto-shredding. <see cref="Sequence"/>,
/// <see cref="PreviousHash"/> and <see cref="Hash"/> are assigned by the single-writer audit sink
/// (infrastructure), not by callers.
/// </summary>
public sealed class AuditEntry
{
    public Guid Id { get; private set; }
    public Guid? TenantId { get; private set; }
    public long Sequence { get; private set; }
    public AuditAction Action { get; private set; }
    public string ResourceType { get; private set; }
    public Guid? ResourceId { get; private set; }
    public Guid? ActorPseudonymId { get; private set; }
    public DateTimeOffset OccurredAt { get; private set; }
    public string PreviousHash { get; private set; }
    public string Hash { get; private set; }

    public AuditEntry(
        Guid id,
        Guid? tenantId,
        long sequence,
        AuditAction action,
        string resourceType,
        Guid? resourceId,
        Guid? actorPseudonymId,
        DateTimeOffset occurredAt,
        string previousHash,
        string hash)
    {
        Id = id;
        TenantId = tenantId;
        Sequence = sequence;
        Action = action;
        ResourceType = resourceType;
        ResourceId = resourceId;
        ActorPseudonymId = actorPseudonymId;
        OccurredAt = occurredAt;
        PreviousHash = previousHash;
        Hash = hash;
    }

    /// <summary>
    /// Seals the entry into the chain: its sequence number, the previous link's hash and its own hash.
    /// Assigned by the single-writer audit-chain interceptor at commit time (not by callers), so the chain
    /// cannot fork or collide under concurrency.
    /// </summary>
    public void Seal(long sequence, string previousHash, string hash)
    {
        Sequence = sequence;
        PreviousHash = previousHash;
        Hash = hash;
    }
}
