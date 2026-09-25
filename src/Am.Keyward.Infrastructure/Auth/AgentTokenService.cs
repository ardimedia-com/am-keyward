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
/// allow agent access and on which its user holds at least Read at issuance; whether it may still reach them is
/// decided again on every request (<see cref="AgentVaultAccess"/>).
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

        var vaultIds = cmd.VaultIds.Distinct().ToList();
        if (vaultIds.Count == 0)
        {
            throw new ArgumentException("An agent token needs at least one vault.", nameof(cmd));
        }

        var now = clock.UtcNow;
        var expiresAt = ResolveExpiry(cmd.ExpiresAt, now);
        var networks = NormalizeNetworks(cmd.AllowedNetworks);

        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        foreach (var vaultId in vaultIds)
        {
            await EnsureVaultCanBeAllowedAsync(db, cmd.UserId, cmd.TenantId, vaultId, ct).ConfigureAwait(false);
        }

        var generated = SoftwareClientTokenGenerator.Generate(Scheme);
        var token = new AgentToken(
            Guid.NewGuid(), cmd.TenantId, cmd.UserId, cmd.Name, generated.Prefix, generated.Hash, cmd.Scopes, networks, now, expiresAt);
        foreach (var vaultId in vaultIds)
        {
            token.AllowVault(vaultId);
        }

        db.AgentTokens.Add(token);
        await audit.AppendAsync(db, new AuditRequest(cmd.TenantId, AuditAction.Create, ResourceType, token.Id, cmd.UserId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);

        return new IssuedAgentToken(token.Id, generated.Token, expiresAt);
    }

    public async Task<IReadOnlyList<AgentTokenSummary>> ListAsync(Guid userId, Guid tenantId, CancellationToken ct = default)
    {
        EnsureScope(userId, tenantId);
        var now = clock.UtcNow;

        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var tokens = await db.AgentTokens.AsNoTracking()
            .Include(t => t.AllowedVaults)
            .Where(t => t.UserId == userId && t.TenantId == tenantId)
            .OrderBy(t => t.Name)
            .ToListAsync(ct)
            .ConfigureAwait(false);

        return tokens
            .Select(t => new AgentTokenSummary(
                t.Id, t.Name, t.Scopes, t.AllowedVaults.Select(v => v.VaultId).ToList(), t.AllowedNetworks,
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
