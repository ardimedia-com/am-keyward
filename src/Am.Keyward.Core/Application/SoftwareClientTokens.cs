namespace Am.Keyward.Core.Application;

/// <summary>Issues a new software-client token for one (project, environment).</summary>
public sealed record IssueSoftwareClientTokenCommand(
    Guid TenantId,
    Guid ProjectId,
    string Environment,
    string Name,
    DateTimeOffset? ExpiresAt,
    Guid? ActorUserId);

/// <summary>
/// The result of issuing or rotating a token. <see cref="Token"/> is the plaintext, returned exactly
/// once and never stored — the caller must hand it to the software client now or it is lost.
/// </summary>
public sealed record IssuedSoftwareClientToken(Guid TokenId, string Token, string TokenPrefix, DateTimeOffset? ExpiresAt);

/// <summary>A non-secret summary of a token for management/listing (never includes the secret or its hash).</summary>
public sealed record SoftwareClientTokenInfo(
    Guid Id,
    Guid ProjectId,
    Guid EnvironmentId,
    string Name,
    string TokenPrefix,
    DateTimeOffset CreatedAt,
    DateTimeOffset? ExpiresAt,
    DateTimeOffset? LastRotatedAt,
    DateTimeOffset? RevokedAt,
    bool IsActive);

/// <summary>Management of software-client tokens (issue / rotate / revoke / list).</summary>
public interface ISoftwareClientTokenService
{
    Task<IssuedSoftwareClientToken> IssueAsync(IssueSoftwareClientTokenCommand command, CancellationToken ct = default);

    Task<IssuedSoftwareClientToken> RotateAsync(Guid tenantId, Guid tokenId, DateTimeOffset? expiresAt, Guid? actorUserId, CancellationToken ct = default);

    Task RevokeAsync(Guid tenantId, Guid tokenId, Guid? actorUserId, CancellationToken ct = default);

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
