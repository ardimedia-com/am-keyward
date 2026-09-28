using System.Net;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Agent;

namespace Am.Keyward.Core.Application;

/// <summary>Lifetime rules for agent tokens: they always expire, by default after 90 days.</summary>
public static class AgentTokenLifetime
{
    public static readonly TimeSpan Default = TimeSpan.FromDays(90);

    public static readonly TimeSpan Maximum = TimeSpan.FromDays(365);
}

/// <summary>
/// Issues an agent token for <see cref="UserId"/> (the signed-in user, whom the token will act as).
/// <para>
/// Vault scopes need at least one vault in <see cref="VaultIds"/>; every one must be a tenant vault of
/// <see cref="TenantId"/> that allows agent access and on which the user holds at least Read.
/// </para>
/// <para>
/// <see cref="AgentScopes.ManageApplications"/> needs a user who may manage the software side, and at least one
/// application in <see cref="ApplicationIds"/> or <see cref="MayCreateApplications"/>. Applications and the
/// create flag without that scope are refused, as are vaults without a vault scope.
/// </para>
/// <see cref="AllowedNetworks"/> is an optional comma-separated CIDR list; <see cref="ExpiresAt"/> defaults to
/// <see cref="AgentTokenLifetime.Default"/>.
/// </summary>
public sealed record IssueAgentTokenCommand(
    Guid UserId,
    Guid TenantId,
    string Name,
    AgentScopes Scopes,
    IReadOnlyList<Guid> VaultIds,
    string? AllowedNetworks = null,
    DateTimeOffset? ExpiresAt = null,
    IReadOnlyList<Guid>? ApplicationIds = null,
    bool MayCreateApplications = false);

/// <summary>The scopes that work on vault items (as opposed to <see cref="AgentScopes.ManageApplications"/>).</summary>
public static class AgentScopeGroups
{
    public const AgentScopes Vault = AgentScopes.VaultList | AgentScopes.VaultRead | AgentScopes.VaultWrite | AgentScopes.VaultReveal;
}

/// <summary>The plaintext token, shown exactly once.</summary>
public sealed record IssuedAgentToken(Guid TokenId, string Token, DateTimeOffset ExpiresAt);

public sealed record AgentTokenSummary(
    Guid Id,
    string Name,
    AgentScopes Scopes,
    IReadOnlyList<Guid> VaultIds,
    IReadOnlyList<Guid> ApplicationIds,
    bool MayCreateApplications,
    string AllowedNetworks,
    DateTimeOffset CreatedAt,
    DateTimeOffset ExpiresAt,
    DateTimeOffset? RevokedAt,
    bool IsActive);

/// <summary>A user's own agent tokens. Every method acts only on tokens the given user issued.</summary>
public interface IAgentTokenService
{
    Task<IssuedAgentToken> IssueAsync(IssueAgentTokenCommand cmd, CancellationToken ct = default);

    Task<IReadOnlyList<AgentTokenSummary>> ListAsync(Guid userId, Guid tenantId, CancellationToken ct = default);

    /// <summary>A new secret on the same token; the old one stops working at once. Expiry defaults to <see cref="AgentTokenLifetime.Default"/>.</summary>
    Task<IssuedAgentToken> RotateAsync(Guid userId, Guid tenantId, Guid tokenId, DateTimeOffset? expiresAt = null, CancellationToken ct = default);

    Task RevokeAsync(Guid userId, Guid tenantId, Guid tokenId, CancellationToken ct = default);
}

/// <summary>An authenticated agent token: who it acts as, in which tenant, with which scopes.</summary>
public sealed record AgentPrincipal(Guid TokenId, Guid TenantId, Guid UserId, AgentScopes Scopes);

/// <summary>
/// Authenticates a presented agent token. Returns null unless the token is genuine and active, its user exists,
/// is not disabled and is still a member of the token's tenant, and <paramref name="clientIp"/> falls in the
/// token's allowed networks (when it has any). Runs on every request.
/// </summary>
public interface IAgentAuthenticator
{
    Task<AgentPrincipal?> AuthenticateAsync(string presentedToken, IPAddress? clientIp, CancellationToken ct = default);
}

/// <summary>
/// The one authorization check for agent requests, evaluated on every request: the token has the scope, the
/// vault is on its allowlist, belongs to the token's tenant and still allows agent access, and the token's user
/// holds <c>permission</c> on it. Anything else — including a vault or item that does not exist — is false.
/// </summary>
public interface IAgentVaultAccess
{
    Task<bool> IsVaultAllowedAsync(Guid tokenId, Guid vaultId, AgentScopes scope, Permission permission, CancellationToken ct = default);

    /// <summary>The same check for the vault the item lives in.</summary>
    Task<bool> IsItemAllowedAsync(Guid tokenId, Guid itemId, AgentScopes scope, Permission permission, CancellationToken ct = default);
}
