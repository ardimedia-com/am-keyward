using Am.Keyward.Core.Domain.Agent;

namespace Am.Keyward.Core.Application;

/// <summary>
/// A reveal request as the agent sees it: never the value, only where it stands — and the entry's stable public id,
/// so the person can be pointed to the entry to copy the value there.
/// </summary>
public sealed record RevealRequestState(
    Guid Id, Guid ItemId, RevealField Field, RevealRequestStatus Status, DateTimeOffset ExpiresAt, DateTimeOffset? ConsumeBy, Guid ItemPublicId);

/// <summary>
/// A pending request as the human deciding it sees it (reason is the agent's untrusted text). <see cref="ItemName"/>
/// is the name when the request was made. <see cref="ItemNameBeforeAgentRename"/> is set when that name was given by
/// an AI agent — show it prominently («renamed by an agent, was …»). <see cref="ItemChangedSinceRequest"/> is true when
/// the item was renamed, moved or changed after the request; <see cref="CurrentItemName"/> is its name now.
/// </summary>
public sealed record PendingRevealRequest(
    Guid Id,
    string TokenName,
    string VaultName,
    string ItemName,
    RevealField Field,
    string Reason,
    DateTimeOffset CreatedAt,
    DateTimeOffset ExpiresAt,
    Guid ItemPublicId,
    string? ItemNameBeforeAgentRename = null,
    bool ItemChangedSinceRequest = false,
    string? CurrentItemName = null);

/// <summary>
/// The agent token already has <see cref="Domain.Agent.RevealRequestLimits.MaxPendingPerToken"/> undecided requests; it
/// must wait for a decision (or expiry) before asking again. Protects the person from approval fatigue.
/// </summary>
public sealed class RevealRequestLimitExceededException(Guid tokenId, int limit)
    : InvalidOperationException($"This agent token already has {limit} reveal requests waiting for a decision; wait until they are decided or expire.")
{
    public Guid TokenId { get; } = tokenId;
}

/// <summary>Outcome of the one-time fetch: the value only when the request was approved and still in its window.</summary>
public sealed record RevealConsumeResult(RevealRequestStatus Status, string? Value);

/// <summary>
/// The reveal flow: an agent requests one secret field, the token's user approves or rejects it in the UI, and an
/// approved request hands the value out exactly once. The agent-side methods run in the agent's request scope
/// (the token's user and tenant); the vault-level check (<see cref="IAgentVaultAccess"/>) is the caller's job.
/// </summary>
public interface IRevealRequestService
{
    /// <summary>
    /// Creates a pending request and notifies the token's user. An undecided request of the same token for the same
    /// item and field is reused (no second notice). Throws <see cref="ArgumentException"/> when the field does not fit
    /// the item, <see cref="RevealRequestLimitExceededException"/> when the token has too many undecided requests.
    /// </summary>
    Task<RevealRequestState> RequestAsync(Guid tokenId, Guid itemId, RevealField field, string reason, CancellationToken ct = default);

    /// <summary>The request of this token, or null.</summary>
    Task<RevealRequestState?> GetAsync(Guid tokenId, Guid requestId, CancellationToken ct = default);

    /// <summary>
    /// The one-time fetch. Returns the value only for an approved request within its window and marks it consumed
    /// first, so of two concurrent calls exactly one gets it. Null when the request is not this token's.
    /// </summary>
    Task<RevealConsumeResult?> ConsumeAsync(Guid tokenId, Guid requestId, CancellationToken ct = default);

    /// <summary>The user's undecided, unexpired requests across their agent tokens.</summary>
    Task<IReadOnlyList<PendingRevealRequest>> ListPendingAsync(Guid userId, Guid tenantId, CancellationToken ct = default);

    Task ApproveAsync(Guid userId, Guid tenantId, Guid requestId, CancellationToken ct = default);

    Task RejectAsync(Guid userId, Guid tenantId, Guid requestId, CancellationToken ct = default);
}
