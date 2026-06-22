using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.ValueObjects;

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

/// <summary>
/// The crypto-shredding link between an audit entry's opaque actor pseudonym and the actor's
/// human-readable PII. The pseudonym (<see cref="Id"/>) is what the audit chain stores; the PII (display
/// name, external id) lives here encrypted under a per-subject DEK. DSGVO erasure destroys the PII
/// (<see cref="Erase"/>) — the ciphertext is cleared so it can never be recovered — while the pseudonym
/// remains in the (immutable) audit chain, keeping it intact and the non-personal metadata auditable.
/// Installation-global: a subject's pseudonym is stable across tenants and not tenant-filtered.
/// </summary>
public sealed class AuditSubject
{
    public Guid Id { get; private set; }

    /// <summary>Stable opaque reference to the real actor (e.g. the <c>AppUser.Id</c>); used for find-or-create and erasure targeting.</summary>
    public string SubjectReference { get; private set; }

    /// <summary>The actor's PII, encrypted at rest. <c>null</c> once erased (crypto-shredded).</summary>
    public EncryptedValue? EncryptedPii { get; private set; }

    public DateTimeOffset CreatedAt { get; private set; }
    public DateTimeOffset? ErasedAt { get; private set; }

    public bool IsErased => ErasedAt is not null;

    // encryptedPii is nullable because an erased subject legitimately has none, and EF reuses this
    // constructor to materialize erased rows. Creation (the directory) always passes a non-null value.
    public AuditSubject(Guid id, string subjectReference, EncryptedValue? encryptedPii, DateTimeOffset createdAt)
    {
        if (string.IsNullOrWhiteSpace(subjectReference))
        {
            throw new ArgumentException("Subject reference required.", nameof(subjectReference));
        }

        Id = id;
        SubjectReference = subjectReference.Trim();
        EncryptedPii = encryptedPii;
        CreatedAt = createdAt;
    }

    /// <summary>Crypto-shred: destroy the encrypted PII so it is irrecoverable, leaving the pseudonym in audit.</summary>
    public void Erase(DateTimeOffset at)
    {
        EncryptedPii = null;
        ErasedAt = at;
    }
}
