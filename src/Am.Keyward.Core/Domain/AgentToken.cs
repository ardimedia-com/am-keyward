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

    /// <summary>
    /// Set up software-client applications: create applications and environments, create/rename/delete secret
    /// keys and set secret values (write-only). Separate from the vault scopes; reaches only the applications on
    /// <see cref="AgentToken.AllowedApplications"/> and those the token created itself. Never app tokens.
    /// </summary>
    ManageApplications = 16,
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
    private readonly List<AgentTokenApplicationAllowance> _allowedApplications = [];

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

    /// <summary>
    /// Days-left bucket of the last expiry notice sent for the current validity (dedupe for the reminder schedule);
    /// reset whenever the validity changes.
    /// </summary>
    public int? LastExpiryNoticeDaysLeft { get; private set; }
    public DateTimeOffset? RevokedAt { get; private set; }

    public IReadOnlyList<AgentTokenVaultAllowance> AllowedVaults => _allowedVaults;

    /// <summary>The existing applications this token may manage (with <see cref="AgentScopes.ManageApplications"/>).</summary>
    public IReadOnlyList<AgentTokenApplicationAllowance> AllowedApplications => _allowedApplications;

    /// <summary>
    /// Whether the token may create new applications (with <see cref="AgentScopes.ManageApplications"/>). An
    /// application it creates stays reachable for it without an allowlist entry.
    /// </summary>
    public bool MayCreateApplications { get; private set; }

    /// <summary>
    /// Reaches every team vault opened to agents — today's and future ones — instead of an allowlist. Each vault must
    /// still be opened to agents and the user must still hold the grant; this only spares listing them.
    /// </summary>
    public bool AllAgentVaults { get; private set; }

    /// <summary>Reaches every application of the tenant — today's and future ones — instead of an allowlist.</summary>
    public bool AllApplications { get; private set; }

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

    public void AllowApplication(Guid projectId)
    {
        if (_allowedApplications.All(a => a.ProjectId != projectId))
        {
            _allowedApplications.Add(new AgentTokenApplicationAllowance(Id, projectId));
        }
    }

    public void AllowCreatingApplications() => MayCreateApplications = true;

    /// <summary>
    /// Sets what the token may do and reach — at issue and on every later edit by its owner. The allowlists are
    /// replaced as a whole; the secret and the validity stay as they are.
    /// </summary>
    public void Configure(
        string name,
        AgentScopes scopes,
        IReadOnlyCollection<Guid> vaultIds,
        bool allAgentVaults,
        IReadOnlyCollection<Guid> applicationIds,
        bool allApplications,
        bool mayCreateApplications,
        string? allowedNetworks)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            throw new ArgumentException("Token name required.", nameof(name));
        }

        if (scopes == AgentScopes.None)
        {
            throw new ArgumentException("An agent token needs at least one scope.", nameof(scopes));
        }

        if (RevokedAt is not null)
        {
            throw new InvalidOperationException("A revoked token cannot be changed.");
        }

        Name = name.Trim();
        Scopes = scopes;
        AllowedNetworks = allowedNetworks?.Trim() ?? string.Empty;
        AllAgentVaults = allAgentVaults;
        AllApplications = allApplications;
        MayCreateApplications = mayCreateApplications;

        _allowedVaults.RemoveAll(v => !vaultIds.Contains(v.VaultId));
        foreach (var vaultId in vaultIds)
        {
            AllowVault(vaultId);
        }

        _allowedApplications.RemoveAll(a => !applicationIds.Contains(a.ProjectId));
        foreach (var applicationId in applicationIds)
        {
            AllowApplication(applicationId);
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
        LastExpiryNoticeDaysLeft = null;
    }

    /// <summary>
    /// A new validity on the same secret: the computer keeps working without being set up again. The validity is
    /// counted from <paramref name="at"/>, like at issue, so a token can never be extended past the maximum.
    /// </summary>
    public void Extend(DateTimeOffset at, DateTimeOffset expiresAt)
    {
        if (RevokedAt is not null)
        {
            throw new InvalidOperationException("A revoked token cannot be extended.");
        }

        if (expiresAt <= at)
        {
            throw new ArgumentException("An agent token must expire in the future.", nameof(expiresAt));
        }

        ExpiresAt = expiresAt;
        LastExpiryNoticeDaysLeft = null;
    }

    public void MarkExpiryNoticeSent(int daysLeft) => LastExpiryNoticeDaysLeft = daysLeft;
}

/// <summary>One existing application (software project) an agent token may manage. Deleted with the application or the token.</summary>
public sealed class AgentTokenApplicationAllowance
{
    public Guid TokenId { get; private set; }
    public Guid ProjectId { get; private set; }

    public AgentTokenApplicationAllowance(Guid tokenId, Guid projectId)
    {
        TokenId = tokenId;
        ProjectId = projectId;
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
