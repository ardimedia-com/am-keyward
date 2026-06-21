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
    public Guid Id { get; }
    public Guid? TenantId { get; }
    public long Sequence { get; }
    public AuditAction Action { get; }
    public string ResourceType { get; }
    public Guid? ResourceId { get; }
    public Guid? ActorPseudonymId { get; }
    public DateTimeOffset OccurredAt { get; }
    public string PreviousHash { get; }
    public string Hash { get; }

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
}
