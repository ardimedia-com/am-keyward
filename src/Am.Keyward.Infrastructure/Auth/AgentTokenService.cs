using System.Net;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Agent;
using Am.Keyward.Core.Domain.ValueObjects;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Am.Keyward.Infrastructure.Auth;

/// <summary>
/// Issues, lists, rotates and revokes a user's own agent tokens. A token can only reach tenant vaults that
/// allow agent access and on which its user holds at least Read at issuance, and — with
/// <see cref="AgentScopes.ManageApplications"/>, which only a software operator may hold — the tenant's
/// applications it lists. Whether it may still reach them is decided again on every request.
/// </summary>
public sealed class AgentTokenService(
    IDbContextFactory<KeywardDbContext> dbFactory,
    IClock clock,
    ICurrentTenant tenant,
    ICurrentUser currentUser,
    IKeywardAccessPolicy authorization,
    DbAuditSink audit) : IAgentTokenService
{
    /// <summary>The leading segment that tells an agent token from a software-client token (<c>amkw</c>).</summary>
    public const string Scheme = "amkwa";

    private const string ResourceType = "AgentToken";

    public async Task<IssuedAgentToken> IssueAsync(IssueAgentTokenCommand cmd, CancellationToken ct = default)
    {
        EnsureScope(cmd.UserId, cmd.TenantId);
        var grants = new Grants(
            cmd.Scopes, cmd.VaultIds.Distinct().ToList(), cmd.AllAgentVaults,
            (cmd.ApplicationIds ?? []).Distinct().ToList(), cmd.AllApplications, cmd.MayCreateApplications);

        var now = clock.UtcNow;
        var expiresAt = ResolveExpiry(cmd.ExpiresAt, now);
        var networks = NormalizeNetworks(cmd.AllowedNetworks);

        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        await ValidateAsync(db, cmd.UserId, cmd.TenantId, grants, ct).ConfigureAwait(false);

        var generated = SoftwareClientTokenGenerator.Generate(Scheme);
        var token = new AgentToken(
            Guid.NewGuid(), cmd.TenantId, cmd.UserId, cmd.Name, generated.Prefix, generated.Hash, cmd.Scopes, networks, now, expiresAt);
        token.Configure(cmd.Name, grants.Scopes, grants.VaultIds, grants.AllAgentVaults, grants.ApplicationIds,
            grants.AllApplications, grants.MayCreateApplications, networks);

        db.AgentTokens.Add(token);
        await audit.AppendAsync(db, new AuditRequest(cmd.TenantId, AuditAction.Create, ResourceType, token.Id, cmd.UserId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);

        return new IssuedAgentToken(token.Id, generated.Token, expiresAt);
    }

    public async Task UpdateAsync(UpdateAgentTokenCommand cmd, CancellationToken ct = default)
    {
        EnsureScope(cmd.UserId, cmd.TenantId);
        var grants = new Grants(
            cmd.Scopes, cmd.VaultIds.Distinct().ToList(), cmd.AllAgentVaults,
            (cmd.ApplicationIds ?? []).Distinct().ToList(), cmd.AllApplications, cmd.MayCreateApplications);
        var networks = NormalizeNetworks(cmd.AllowedNetworks);

        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);

        // Ownership first: someone else's token is simply not found, whatever was asked for.
        var token = await db.AgentTokens
            .Include(t => t.AllowedVaults)
            .Include(t => t.AllowedApplications)
            .FirstOrDefaultAsync(t => t.Id == cmd.TokenId && t.UserId == cmd.UserId && t.TenantId == cmd.TenantId, ct)
            .ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Agent token {cmd.TokenId} not found.");

        await ValidateAsync(db, cmd.UserId, cmd.TenantId, grants, ct).ConfigureAwait(false);

        token.Configure(cmd.Name, grants.Scopes, grants.VaultIds, grants.AllAgentVaults, grants.ApplicationIds,
            grants.AllApplications, grants.MayCreateApplications, networks);
        await audit.AppendAsync(db, new AuditRequest(cmd.TenantId, AuditAction.Update, ResourceType, token.Id, cmd.UserId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    private sealed record Grants(
        AgentScopes Scopes,
        IReadOnlyList<Guid> VaultIds,
        bool AllAgentVaults,
        IReadOnlyList<Guid> ApplicationIds,
        bool AllApplications,
        bool MayCreateApplications);

    // The one rule set for issuing and editing: vault permissions need a vault (or «all vaults opened to agents") and
    // the other way round; «Manage applications» needs an application, «all applications» or «may create», and a user
    // who may manage the software side.
    private async Task ValidateAsync(KeywardDbContext db, Guid userId, Guid tenantId, Grants grants, CancellationToken ct)
    {
        var hasVaultScope = (grants.Scopes & AgentScopeGroups.Vault) != 0;
        var hasVaults = grants.VaultIds.Count > 0 || grants.AllAgentVaults;
        if (hasVaultScope != hasVaults)
        {
            throw new ArgumentException(hasVaultScope
                ? "An agent token with vault permissions needs at least one vault."
                : "Vaults need at least one vault permission.");
        }

        var managesApplications = (grants.Scopes & AgentScopes.ManageApplications) != 0;
        var hasApplications = grants.ApplicationIds.Count > 0 || grants.AllApplications || grants.MayCreateApplications;
        if (managesApplications != hasApplications)
        {
            throw new ArgumentException(managesApplications
                ? "Managing applications needs at least one application or the permission to create new ones."
                : "Applications need the permission to manage applications.");
        }

        foreach (var vaultId in grants.VaultIds)
        {
            await EnsureVaultCanBeAllowedAsync(db, userId, tenantId, vaultId, ct).ConfigureAwait(false);
        }

        if (managesApplications)
        {
            await EnsureApplicationsCanBeAllowedAsync(db, userId, tenantId, grants.ApplicationIds, ct).ConfigureAwait(false);
        }
    }

    public async Task<IReadOnlyList<AgentTokenSummary>> ListAsync(Guid userId, Guid tenantId, CancellationToken ct = default)
    {
        EnsureScope(userId, tenantId);
        var now = clock.UtcNow;

        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var tokens = await db.AgentTokens.AsNoTracking()
            .Include(t => t.AllowedVaults)
            .Include(t => t.AllowedApplications)
            .Where(t => t.UserId == userId && t.TenantId == tenantId)
            .OrderBy(t => t.Name)
            .ToListAsync(ct)
            .ConfigureAwait(false);

        return tokens
            .Select(t => new AgentTokenSummary(
                t.Id, t.Name, t.Scopes, t.AllowedVaults.Select(v => v.VaultId).ToList(),
                t.AllowedApplications.Select(a => a.ProjectId).ToList(), t.MayCreateApplications, t.AllAgentVaults, t.AllApplications,
                t.AllowedNetworks,
                t.CreatedAt, t.ExpiresAt, t.RevokedAt, t.IsActive(now)))
            .ToList();
    }

    public async Task<IssuedAgentToken> RotateAsync(Guid userId, Guid tenantId, Guid tokenId, DateTimeOffset? expiresAt = null, CancellationToken ct = default)
    {
        EnsureScope(userId, tenantId);
        var now = clock.UtcNow;
        var expiry = ResolveExpiry(expiresAt, now);

        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var token = await LoadOwnAsync(db, userId, tenantId, tokenId, ct).ConfigureAwait(false);

        var generated = SoftwareClientTokenGenerator.Generate(Scheme);
        token.Rotate(generated.Prefix, generated.Hash, now, expiry);
        await audit.AppendAsync(db, new AuditRequest(tenantId, AuditAction.Update, ResourceType, token.Id, userId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);

        return new IssuedAgentToken(token.Id, generated.Token, expiry);
    }

    public async Task RevokeAsync(Guid userId, Guid tenantId, Guid tokenId, CancellationToken ct = default)
    {
        EnsureScope(userId, tenantId);

        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var token = await LoadOwnAsync(db, userId, tenantId, tokenId, ct).ConfigureAwait(false);

        token.Revoke(clock.UtcNow);
        await audit.AppendAsync(db, new AuditRequest(tenantId, AuditAction.Revoke, ResourceType, token.Id, userId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    // The token table is installation-global (no tenant filter): ownership is the user + tenant match.
    private static async Task<AgentToken> LoadOwnAsync(KeywardDbContext db, Guid userId, Guid tenantId, Guid tokenId, CancellationToken ct) =>
        await db.AgentTokens
            .FirstOrDefaultAsync(t => t.Id == tokenId && t.UserId == userId && t.TenantId == tenantId, ct)
            .ConfigureAwait(false)
        ?? throw new InvalidOperationException($"Agent token {tokenId} not found.");

    private async Task EnsureVaultCanBeAllowedAsync(KeywardDbContext db, Guid userId, Guid tenantId, Guid vaultId, CancellationToken ct)
    {
        var vault = await db.Vaults.AsNoTracking()
            .FirstOrDefaultAsync(v => v.Id == vaultId, ct)
            .ConfigureAwait(false);

        if (vault is null || vault.TenantId != tenantId)
        {
            throw new InvalidOperationException($"Vault {vaultId} not found in tenant {tenantId}.");
        }

        if (!vault.AgentAccessAllowed || vault.ProtectionMode != ProtectionMode.ServerSide)
        {
            throw new InvalidOperationException($"Vault {vaultId} does not allow agent access.");
        }

        if (!await authorization.IsAllowedAsync(userId, new GrantScope(GrantScopeKind.Vault, vaultId), Permission.Read, ct).ConfigureAwait(false))
        {
            throw new UnauthorizedAccessException($"Not authorized for vault {vaultId}.");
        }
    }

    // Managing applications is a software-operator task (the same predicate the application pages use), so only
    // an operator can hand it to an agent. It is checked again on every request, since the role can be withdrawn.
    private static async Task EnsureApplicationsCanBeAllowedAsync(
        KeywardDbContext db, Guid userId, Guid tenantId, IReadOnlyList<Guid> applicationIds, CancellationToken ct)
    {
        if (!await SoftwareOperatorGuard.IsOperatorAsync(db, tenantId, userId, ct).ConfigureAwait(false))
        {
            throw new UnauthorizedAccessException("Only a user who may manage applications can give an agent token that permission.");
        }

        var found = await db.Projects.AsNoTracking()
            .Where(p => applicationIds.Contains(p.Id) && p.TenantId == tenantId)
            .Select(p => p.Id)
            .ToListAsync(ct)
            .ConfigureAwait(false);
        var missing = applicationIds.Except(found).ToList();
        if (missing.Count > 0)
        {
            throw new InvalidOperationException($"Application {missing[0]} not found in tenant {tenantId}.");
        }
    }

    private static DateTimeOffset ResolveExpiry(DateTimeOffset? requested, DateTimeOffset now)
    {
        var expiresAt = requested ?? now + AgentTokenLifetime.Default;
        if (expiresAt <= now)
        {
            throw new ArgumentException("An agent token must expire in the future.");
        }

        if (expiresAt > now + AgentTokenLifetime.Maximum)
        {
            throw new ArgumentException($"An agent token may be valid for at most {AgentTokenLifetime.Maximum.TotalDays:0} days.");
        }

        return expiresAt;
    }

    /// <summary>Validates and normalizes a comma-separated CIDR list; empty means any network.</summary>
    internal static string NormalizeNetworks(string? networks)
    {
        if (string.IsNullOrWhiteSpace(networks))
        {
            return string.Empty;
        }

        var parsed = networks
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(n => IPNetwork.TryParse(n, out var network)
                ? network.ToString()
                : throw new ArgumentException($"'{n}' is not a network in CIDR notation (e.g. 10.0.0.0/8)."))
            .Distinct();
        return string.Join(',', parsed);
    }

    private void EnsureScope(Guid userId, Guid tenantId)
    {
        if (currentUser.UserId != userId)
        {
            throw new UnauthorizedAccessException("User scope mismatch: agent tokens are managed only by their own user.");
        }

        if (tenant.TenantId != tenantId)
        {
            throw new UnauthorizedAccessException("Tenant scope mismatch: the request's tenant does not match the authenticated scope.");
        }
    }
}
