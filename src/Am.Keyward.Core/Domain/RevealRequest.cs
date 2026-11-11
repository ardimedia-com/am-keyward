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

    /// <summary>
    /// A Login's current one-time code (2FA, decision T16 A). Generated at the moment it is handed over — never the
    /// 2FA key itself.
    /// </summary>
    Totp,
}

public enum RevealRequestStatus
{
    Pending,
    Approved,
    Rejected,
    Expired,
    Consumed,

    /// <summary>
    /// Withdrawn by the system before a decision: the same agent token changed the item (renamed it or changed its
    /// value) while the request was pending, so what the person would approve is no longer what was asked for.
    /// </summary>
    Voided,
}

/// <summary>Bounds that keep reveal requests from flooding the person who decides them.</summary>
public static class RevealRequestLimits
{
    /// <summary>At most this many undecided, unexpired requests per agent token.</summary>
    public const int MaxPendingPerToken = 3;
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

    /// <summary>The item's name when the request was made — what the person is shown, whatever the item is called later.</summary>
    public string ItemNameAtRequest { get; private set; }

    /// <summary>
    /// The name the item had before an AI agent renamed it, when its name at request time came from an agent (see
    /// <see cref="Human.VaultItem.NameBeforeAgentRename"/>). Shown next to <see cref="ItemNameAtRequest"/> so a rename
    /// to something harmless-looking cannot hide what is really being asked for.
    /// </summary>
    public string? ItemNameBeforeAgentRename { get; private set; }

    /// <summary>The item's revision when the request was made; a different revision later means the item changed since.</summary>
    public Guid ItemRevisionAtRequest { get; private set; }

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

    public RevealRequest(
        Guid id,
        Guid tenantId,
        Guid tokenId,
        Guid userId,
        Guid itemId,
        RevealField field,
        string reason,
        DateTimeOffset createdAt,
        string itemNameAtRequest,
        Guid itemRevisionAtRequest,
        string? itemNameBeforeAgentRename = null)
    {
        if (string.IsNullOrWhiteSpace(itemNameAtRequest))
        {
            throw new ArgumentException("The item name at request time is required.", nameof(itemNameAtRequest));
        }

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
        ItemNameAtRequest = itemNameAtRequest;
        ItemNameBeforeAgentRename = string.IsNullOrWhiteSpace(itemNameBeforeAgentRename) ? null : itemNameBeforeAgentRename;
        ItemRevisionAtRequest = itemRevisionAtRequest;
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

    /// <summary>
    /// Withdraws a still-pending request (see <see cref="RevealRequestStatus.Voided"/>). Returns false when it was no
    /// longer pending — a decided request is left as it is.
    /// </summary>
    public bool Void(DateTimeOffset at)
    {
        if (StatusAt(at) != RevealRequestStatus.Pending)
        {
            return false;
        }

        Status = RevealRequestStatus.Voided;
        DecidedAt = at;
        return true;
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
