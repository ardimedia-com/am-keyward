using Am.Keyward.Core.Domain.ValueObjects;

namespace Am.Keyward.Core.Domain.Access;

/// <summary>
/// A dual-control emergency-access grant. A System Admin <em>requests</em> break-glass access to a
/// server-side resource (a vault / project / environment) with a reason; a <em>different</em> System Admin
/// must <em>approve</em> it before it can be consumed, and only within a short validity window. The
/// approver-must-differ rule (no self-approval) is the dual control; combined with the non-repudiable
/// external sink record written on approval, this is the "mechanism, not an adjective" the design requires.
/// </summary>
public sealed class BreakGlassGrant
{
    public Guid Id { get; private set; }

    /// <summary>Tenant of the target resource (null for a tenant-less personal resource).</summary>
    public Guid? TenantId { get; private set; }

    /// <summary>What is being recovered.</summary>
    public GrantScope Scope { get; private set; } = null!;

    public Guid RequesterUserId { get; private set; }
    public string Reason { get; private set; } = null!;
    public BreakGlassStatus Status { get; private set; }
    public Guid? ApproverUserId { get; private set; }
    public DateTimeOffset RequestedAt { get; private set; }
    public DateTimeOffset? DecidedAt { get; private set; }
    public DateTimeOffset ExpiresAt { get; private set; }
    public DateTimeOffset? ConsumedAt { get; private set; }

    /// <summary>
    /// Optimistic-concurrency token (mapped as a SQL Server rowversion). It makes every state transition
    /// serialize at the database: two concurrent approve/reject/consume calls cannot both win — the second
    /// save fails, so an approved single-use grant cannot be consumed twice.
    /// </summary>
    public byte[]? RowVersion { get; private set; }

    private BreakGlassGrant() { } // EF: owned GrantScope cannot be bound via constructor, so EF builds it separately.

    public BreakGlassGrant(
        Guid id, Guid? tenantId, GrantScope scope, Guid requesterUserId, string reason,
        DateTimeOffset requestedAt, DateTimeOffset expiresAt)
    {
        if (string.IsNullOrWhiteSpace(reason))
        {
            throw new ArgumentException("A break-glass request must state a reason.", nameof(reason));
        }

        if (expiresAt <= requestedAt)
        {
            throw new ArgumentException("Break-glass validity window must be positive.", nameof(expiresAt));
        }

        Id = id;
        TenantId = tenantId;
        Scope = scope ?? throw new ArgumentNullException(nameof(scope));
        RequesterUserId = requesterUserId;
        Reason = reason.Trim();
        Status = BreakGlassStatus.Pending;
        RequestedAt = requestedAt;
        ExpiresAt = expiresAt;
    }

    /// <summary>Approve the request. Enforces dual control: the approver must differ from the requester.</summary>
    public void Approve(Guid approverUserId, DateTimeOffset at)
    {
        if (Status != BreakGlassStatus.Pending)
        {
            throw new InvalidOperationException($"Break-glass grant is {Status}, not pending.");
        }

        if (approverUserId == RequesterUserId)
        {
            throw new InvalidOperationException("Dual control: a break-glass request cannot be approved by its requester.");
        }

        Status = BreakGlassStatus.Approved;
        ApproverUserId = approverUserId;
        DecidedAt = at;
    }

    public void Reject(Guid approverUserId, DateTimeOffset at)
    {
        if (Status != BreakGlassStatus.Pending)
        {
            throw new InvalidOperationException($"Break-glass grant is {Status}, not pending.");
        }

        Status = BreakGlassStatus.Rejected;
        ApproverUserId = approverUserId;
        DecidedAt = at;
    }

    /// <summary>Whether the grant currently authorizes emergency access (approved and not expired).</summary>
    public bool IsUsable(DateTimeOffset now) => Status == BreakGlassStatus.Approved && now < ExpiresAt;

    /// <summary>Consume an approved, unexpired grant for a single recovery; marks it spent.</summary>
    public void Consume(DateTimeOffset at)
    {
        if (Status == BreakGlassStatus.Approved && at >= ExpiresAt)
        {
            Status = BreakGlassStatus.Expired;
        }

        if (Status != BreakGlassStatus.Approved)
        {
            throw new InvalidOperationException($"Break-glass grant is {Status}; it cannot be consumed.");
        }

        Status = BreakGlassStatus.Consumed;
        ConsumedAt = at;
    }
}
