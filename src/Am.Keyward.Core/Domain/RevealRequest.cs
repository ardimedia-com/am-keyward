namespace Am.Keyward.Core.Domain.Agent;

/// <summary>The one secret field of an item an agent may ask to see.</summary>
public enum RevealField
{
    /// <summary>A Login password.</summary>
    Password,

    /// <summary>A Login note.</summary>
    Note,

    /// <summary>The whole value of any other item type.</summary>
    Value,
}

public enum RevealRequestStatus
{
    Pending,
    Approved,
    Rejected,
    Expired,
    Consumed,
}

/// <summary>How long each step of a reveal may take.</summary>
public static class RevealRequestLifetime
{
    /// <summary>An undecided request expires after this.</summary>
    public static readonly TimeSpan Pending = TimeSpan.FromMinutes(5);

    /// <summary>An approved request must be consumed within this; the value is handed out once.</summary>
    public static readonly TimeSpan ConsumeWindow = TimeSpan.FromSeconds(60);
}

/// <summary>
/// An agent asking to see one secret field of one item. Nothing is revealed until the token's own user approves
/// the request in the Keyward UI; the value is then handed out exactly once, within
/// <see cref="RevealRequestLifetime.ConsumeWindow"/>. The reason is the agent's own text: shown to the human as
/// plain text, never trusted — the human's decision per request is the control, not the reason.
/// </summary>
public sealed class RevealRequest
{
    public const int MaxReasonLength = 500;

    public Guid Id { get; private set; }
    public Guid TenantId { get; private set; }
    public Guid TokenId { get; private set; }

    /// <summary>The token's user — the only one who may approve or reject.</summary>
    public Guid UserId { get; private set; }

    public Guid ItemId { get; private set; }
    public RevealField Field { get; private set; }
    public string Reason { get; private set; }
    public RevealRequestStatus Status { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }

    /// <summary>Deadline for the decision.</summary>
    public DateTimeOffset ExpiresAt { get; private set; }

    public DateTimeOffset? DecidedAt { get; private set; }

    /// <summary>Deadline for the one-time fetch, set on approval.</summary>
    public DateTimeOffset? ConsumeBy { get; private set; }

    public DateTimeOffset? ConsumedAt { get; private set; }

    /// <summary>
    /// Optimistic-concurrency token (SQL Server rowversion): every transition serializes at the database, so an
    /// approved request cannot be consumed twice and a decision cannot race another.
    /// </summary>
    public byte[]? RowVersion { get; private set; }

    public RevealRequest(Guid id, Guid tenantId, Guid tokenId, Guid userId, Guid itemId, RevealField field, string reason, DateTimeOffset createdAt)
    {
        if (string.IsNullOrWhiteSpace(reason))
        {
            throw new ArgumentException("A reveal request must state a reason.", nameof(reason));
        }

        if (reason.Trim().Length > MaxReasonLength)
        {
            throw new ArgumentException($"The reason may be at most {MaxReasonLength} characters.", nameof(reason));
        }

        Id = id;
        TenantId = tenantId;
        TokenId = tokenId;
        UserId = userId;
        ItemId = itemId;
        Field = field;
        Reason = reason.Trim();
        Status = RevealRequestStatus.Pending;
        CreatedAt = createdAt;
        ExpiresAt = createdAt + RevealRequestLifetime.Pending;
    }

    /// <summary>The status as of <paramref name="now"/>: a missed deadline reads as expired even before it is stored.</summary>
    public RevealRequestStatus StatusAt(DateTimeOffset now) => Status switch
    {
        RevealRequestStatus.Pending when now >= ExpiresAt => RevealRequestStatus.Expired,
        RevealRequestStatus.Approved when now >= ConsumeBy => RevealRequestStatus.Expired,
        _ => Status,
    };

    public void Approve(Guid userId, DateTimeOffset at)
    {
        EnsureDecidable(userId, at);
        Status = RevealRequestStatus.Approved;
        DecidedAt = at;
        ConsumeBy = at + RevealRequestLifetime.ConsumeWindow;
    }

    public void Reject(Guid userId, DateTimeOffset at)
    {
        EnsureDecidable(userId, at);
        Status = RevealRequestStatus.Rejected;
        DecidedAt = at;
    }

    /// <summary>Marks the one-time fetch; throws unless the request is approved and still within its window.</summary>
    public void Consume(DateTimeOffset at)
    {
        if (StatusAt(at) != RevealRequestStatus.Approved)
        {
            throw new InvalidOperationException($"The reveal request is {StatusAt(at)}, not approved.");
        }

        Status = RevealRequestStatus.Consumed;
        ConsumedAt = at;
    }

    private void EnsureDecidable(Guid userId, DateTimeOffset at)
    {
        if (userId != UserId)
        {
            throw new UnauthorizedAccessException("Only the user the agent token acts for decides its reveal requests.");
        }

        if (StatusAt(at) != RevealRequestStatus.Pending)
        {
            throw new InvalidOperationException($"The reveal request is {StatusAt(at)}, not pending.");
        }
    }
}
