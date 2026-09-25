namespace Am.Keyward.Core.Domain.Agent;

/// <summary>What an agent token may do. A token carries any combination; each endpoint requires one.</summary>
[Flags]
public enum AgentScopes
{
    None = 0,

    /// <summary>List the allowlisted vaults, their folders and item names/types (cleartext only).</summary>
    VaultList = 1,

    /// <summary>Read one item's non-secret fields (a Login's url and username).</summary>
    VaultRead = 2,

    /// <summary>Create items and change their values (never echoed back).</summary>
    VaultWrite = 4,

    /// <summary>Request a secret value, which a human must approve per request.</summary>
    VaultReveal = 8,
}

/// <summary>
/// A credential an AI agent presents (as a Bearer token) to work with vault items <b>on behalf of the user who
/// issued it</b>: every request runs as that user, so their grants apply, and is audited as
/// <see cref="ActorKind.Agent"/> with this token. Access is narrowed further by <see cref="Scopes"/>, the
/// explicit vault allowlist (<see cref="AllowedVaults"/>) and optionally the caller's network
/// (<see cref="AllowedNetworks"/>). Only a hash of the token is stored; the plaintext is shown once. Like
/// <see cref="Software.SoftwareClientToken"/> the table is installation-global (looked up before the tenant is
/// known).
/// </summary>
public sealed class AgentToken
{
    private readonly List<AgentTokenVaultAllowance> _allowedVaults = [];

    public Guid Id { get; private set; }
    public Guid TenantId { get; private set; }

    /// <summary>The issuing user, whom every request of this token acts as.</summary>
    public Guid UserId { get; private set; }

    public string Name { get; private set; }

    /// <summary>Non-secret, indexed lookup handle (the middle segment of the token).</summary>
    public string TokenPrefix { get; private set; }

    /// <summary>SHA-256 (hex) of the full token string. The plaintext token is never stored.</summary>
    public string TokenHash { get; private set; }

    public AgentScopes Scopes { get; private set; }

    /// <summary>
    /// Comma-separated CIDR ranges the token may be used from (e.g. <c>10.0.0.0/8,192.168.10.0/24</c>); empty
    /// means any network.
    /// </summary>
    public string AllowedNetworks { get; private set; }

    public DateTimeOffset CreatedAt { get; private set; }

    /// <summary>Agent tokens always expire.</summary>
    public DateTimeOffset ExpiresAt { get; private set; }

    public DateTimeOffset? LastRotatedAt { get; private set; }
    public DateTimeOffset? RevokedAt { get; private set; }

    public IReadOnlyList<AgentTokenVaultAllowance> AllowedVaults => _allowedVaults;

    public AgentToken(
        Guid id,
        Guid tenantId,
        Guid userId,
        string name,
        string tokenPrefix,
        string tokenHash,
        AgentScopes scopes,
        string? allowedNetworks,
        DateTimeOffset createdAt,
        DateTimeOffset expiresAt)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            throw new ArgumentException("Token name required.", nameof(name));
        }

        if (string.IsNullOrWhiteSpace(tokenPrefix) || string.IsNullOrWhiteSpace(tokenHash))
        {
            throw new ArgumentException("Token prefix and hash required.");
        }

        if (scopes == AgentScopes.None)
        {
            throw new ArgumentException("An agent token needs at least one scope.", nameof(scopes));
        }

        if (expiresAt <= createdAt)
        {
            throw new ArgumentException("An agent token must expire after it is created.", nameof(expiresAt));
        }

        Id = id;
        TenantId = tenantId;
        UserId = userId;
        Name = name.Trim();
        TokenPrefix = tokenPrefix;
        TokenHash = tokenHash;
        Scopes = scopes;
        AllowedNetworks = allowedNetworks?.Trim() ?? string.Empty;
        CreatedAt = createdAt;
        ExpiresAt = expiresAt;
    }

    public bool IsActive(DateTimeOffset now) => RevokedAt is null && ExpiresAt > now;

    public bool Allows(AgentScopes scope) => scope != AgentScopes.None && (Scopes & scope) == scope;

    public void AllowVault(Guid vaultId)
    {
        if (_allowedVaults.All(v => v.VaultId != vaultId))
        {
            _allowedVaults.Add(new AgentTokenVaultAllowance(Id, vaultId));
        }
    }

    public void Revoke(DateTimeOffset at) => RevokedAt ??= at;

    /// <summary>Replaces the secret (the previous token stops working immediately) with a fresh validity window.</summary>
    public void Rotate(string newPrefix, string newHash, DateTimeOffset at, DateTimeOffset expiresAt)
    {
        if (RevokedAt is not null)
        {
            throw new InvalidOperationException("Cannot rotate a revoked token.");
        }

        if (string.IsNullOrWhiteSpace(newPrefix) || string.IsNullOrWhiteSpace(newHash))
        {
            throw new ArgumentException("New token prefix and hash required.");
        }

        if (expiresAt <= at)
        {
            throw new ArgumentException("An agent token must expire after it is rotated.", nameof(expiresAt));
        }

        TokenPrefix = newPrefix;
        TokenHash = newHash;
        LastRotatedAt = at;
        CreatedAt = at;
        ExpiresAt = expiresAt;
    }
}

/// <summary>One vault an agent token may reach. Deleted with the vault or the token.</summary>
public sealed class AgentTokenVaultAllowance
{
    public Guid TokenId { get; private set; }
    public Guid VaultId { get; private set; }

    public AgentTokenVaultAllowance(Guid tokenId, Guid vaultId)
    {
        TokenId = tokenId;
        VaultId = vaultId;
    }
}
