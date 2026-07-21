namespace Am.Keyward.Core.Application;

/// <summary>
/// Issues a new software-client token for one (project, environment). An empty <see cref="Name"/> gets the
/// default "&lt;application&gt;-&lt;environment&gt;" (numbered when already taken); a given name must be
/// unique within the project.
/// </summary>
public sealed record IssueSoftwareClientTokenCommand(
    Guid TenantId,
    Guid ProjectId,
    string Environment,
    string Name,
    DateTimeOffset? ExpiresAt,
    Guid? ActorUserId,
    string Note = "");

/// <summary>
/// The result of issuing or rotating a token. <see cref="Token"/> is the plaintext, returned exactly
/// once and never stored — the caller must hand it to the software client now or it is lost.
/// </summary>
public sealed record IssuedSoftwareClientToken(Guid TokenId, string Token, string TokenPrefix, DateTimeOffset? ExpiresAt);

/// <summary>What a rotation should do with the validity window. A plain nullable date could not express all
/// three intents (null was overloaded as "keep", leaving no way to say "never"), so rotation takes this
/// explicit choice instead.</summary>
public enum TokenExpiryKind
{
    /// <summary>Re-apply the token's current lifetime from now (a 30-day token becomes a fresh 30-day token).</summary>
    Keep,

    /// <summary>The rotated token never expires.</summary>
    Never,

    /// <summary>The rotated token expires at <see cref="TokenExpiryChange.At"/>.</summary>
    On,
}

/// <summary>An explicit expiry intent for <see cref="ISoftwareClientTokenService.RotateAsync"/>.</summary>
public readonly record struct TokenExpiryChange(TokenExpiryKind Kind, DateTimeOffset? At)
{
    /// <summary>Re-apply the current lifetime from now.</summary>
    public static readonly TokenExpiryChange Keep = new(TokenExpiryKind.Keep, null);

    /// <summary>Rotate to a token that never expires.</summary>
    public static readonly TokenExpiryChange Never = new(TokenExpiryKind.Never, null);

    /// <summary>Rotate to a token that expires at <paramref name="at"/>.</summary>
    public static TokenExpiryChange On(DateTimeOffset at) => new(TokenExpiryKind.On, at);

    /// <summary>Bridge for callers that only have a nullable date and want the historic "null = keep" behavior
    /// (e.g. the management API): a value maps to <see cref="On"/>, null to <see cref="Keep"/>.</summary>
    public static TokenExpiryChange FromNullableKeep(DateTimeOffset? at) => at is { } d ? On(d) : Keep;
}

/// <summary>A non-secret summary of a token for management/listing (never includes the secret or its hash).</summary>
public sealed record SoftwareClientTokenInfo(
    Guid Id,
    Guid ProjectId,
    Guid EnvironmentId,
    string Name,
    string Note,
    string TokenPrefix,
    DateTimeOffset CreatedAt,
    DateTimeOffset? ExpiresAt,
    DateTimeOffset? LastRotatedAt,
    DateTimeOffset? RevokedAt,
    bool IsActive,
    bool HasSecret);

/// <summary>Management of software-client tokens (issue / rotate / revoke / list).</summary>
public interface ISoftwareClientTokenService
{
    Task<IssuedSoftwareClientToken> IssueAsync(IssueSoftwareClientTokenCommand command, CancellationToken ct = default);

    /// <summary>
    /// Creates a pending placeholder token for one environment (default-named, no secret yet — it cannot
    /// authenticate until its first value is minted via <see cref="RotateAsync"/>). Used when an
    /// application or environment is created, so every environment starts with a visible token slot.
    /// </summary>
    Task<Guid> CreatePendingAsync(Guid tenantId, Guid projectId, Guid environmentId, Guid? actorUserId, CancellationToken ct = default);

    Task<IssuedSoftwareClientToken> RotateAsync(Guid tenantId, Guid tokenId, TokenExpiryChange expiry, Guid? actorUserId, CancellationToken ct = default);

    /// <summary>Updates a token's name and note (does not change its secret, scope or expiry).</summary>
    Task UpdateAsync(Guid tenantId, Guid tokenId, string name, string note, Guid? actorUserId, CancellationToken ct = default);

    Task RevokeAsync(Guid tenantId, Guid tokenId, Guid? actorUserId, CancellationToken ct = default);

    /// <summary>Undoes a revocation — the token's existing secret authenticates again (expiry unchanged).</summary>
    Task ReactivateAsync(Guid tenantId, Guid tokenId, Guid? actorUserId, CancellationToken ct = default);

    /// <summary>Permanently deletes a token record; software still presenting it is rejected immediately.</summary>
    Task DeleteAsync(Guid tenantId, Guid tokenId, Guid? actorUserId, CancellationToken ct = default);

    Task<IReadOnlyList<SoftwareClientTokenInfo>> ListAsync(Guid tenantId, Guid projectId, CancellationToken ct = default);
}

/// <summary>The scope a presented software-client token resolves to (server-authoritative, from the record).</summary>
public sealed record SoftwareClientPrincipal(Guid TokenId, Guid TenantId, Guid ProjectId, Guid EnvironmentId);

/// <summary>Authenticates a presented software-client token, returning its scope or null when invalid.</summary>
public interface ISoftwareClientAuthenticator
{
    Task<SoftwareClientPrincipal?> AuthenticateAsync(string presentedToken, CancellationToken ct = default);
}

/// <summary>
/// Reads software secrets for an already-resolved (project, environment) — the software-client path,
/// where the environment is fixed by the authenticated token rather than named by the caller.
/// </summary>
public interface ISoftwareSecretReader
{
    Task<string?> ReadAsync(Guid tenantId, Guid projectId, Guid environmentId, string key, Guid? actorUserId, CancellationToken ct = default);

    /// <summary>All current key/value pairs for the environment (the IConfiguration bulk-load case).</summary>
    Task<IReadOnlyList<KeyValuePair<string, string>>> ReadAllAsync(Guid tenantId, Guid projectId, Guid environmentId, Guid? actorUserId, CancellationToken ct = default);
}
