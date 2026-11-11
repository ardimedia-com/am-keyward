using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Agent;
using Am.Keyward.Core.Domain.ValueObjects;
using Am.Keyward.Infrastructure.Persistence;
using Am.Keyward.Infrastructure.Tenancy;
using Microsoft.EntityFrameworkCore;

namespace Am.Keyward.Infrastructure.Auth;

/// <summary>
/// The single authorization decision for agent requests, made on every request from the current database state:
/// clearing a vault's agent flag, dropping it from the allowlist, revoking the user's grant or the token itself
/// takes effect on the next call. Must run in the token's tenant scope (the agent handler sets it).
/// <para>
/// <see cref="FilterAllowedVaultsAsync"/> is the same decision for many vaults at once (listing, search): one
/// context and a fixed number of queries instead of a context and up to five queries per vault.
/// </para>
/// </summary>
public sealed class AgentVaultAccess(
    IDbContextFactory<KeywardDbContext> dbFactory,
    IClock clock,
    ICurrentTenant tenant,
    IKeywardAccessPolicy authorization) : IAgentVaultAccess, IAgentVaultFilter
{
    public async Task<bool> IsVaultAllowedAsync(Guid tokenId, Guid vaultId, AgentScopes scope, Permission permission, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        return await IsAllowedAsync(db, tokenId, vaultId, scope, permission, ct).ConfigureAwait(false);
    }

    public async Task<bool> IsItemAllowedAsync(Guid tokenId, Guid itemId, AgentScopes scope, Permission permission, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var vaultId = await db.VaultItems.AsNoTracking()
            .Where(i => i.Id == itemId)
            .Select(i => (Guid?)i.VaultId)
            .FirstOrDefaultAsync(ct)
            .ConfigureAwait(false);

        return vaultId is { } id && await IsAllowedAsync(db, tokenId, id, scope, permission, ct).ConfigureAwait(false);
    }

    public async Task<IReadOnlySet<Guid>> FilterAllowedVaultsAsync(
        Guid tokenId, IReadOnlyCollection<Guid> vaultIds, AgentScopes scope, Permission permission, CancellationToken ct = default)
    {
        var allowed = new HashSet<Guid>();
        if (vaultIds.Count == 0)
        {
            return allowed;
        }

        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var token = await db.AgentTokens.AsNoTracking()
            .FirstOrDefaultAsync(t => t.Id == tokenId, ct)
            .ConfigureAwait(false);
        if (token is null || !token.IsActive(clock.UtcNow) || !token.Allows(scope) || tenant.TenantId != token.TenantId)
        {
            return allowed;
        }

        var candidates = vaultIds.Distinct().ToList();
        if (!token.AllAgentVaults)
        {
            var allowlisted = await db.AgentTokenVaultAllowances.AsNoTracking()
                .Where(a => a.TokenId == tokenId && candidates.Contains(a.VaultId))
                .Select(a => a.VaultId)
                .ToListAsync(ct)
                .ConfigureAwait(false);
            candidates = allowlisted;
        }

        if (candidates.Count == 0)
        {
            return allowed;
        }

        // Through the tenant filter (and row-level security), exactly like the single check.
        var vaults = await db.Vaults.AsNoTracking()
            .Where(v => candidates.Contains(v.Id))
            .Select(v => new { v.Id, v.TenantId, v.OwnerUserId, v.AgentAccessAllowed, v.ProtectionMode })
            .ToListAsync(ct)
            .ConfigureAwait(false);

        var tenantVaults = new List<Guid>();
        foreach (var vault in vaults.Where(v => v.AgentAccessAllowed && v.ProtectionMode == ProtectionMode.ServerSide))
        {
            if (vault.TenantId is null)
            {
                // A personal vault: only its owner's tokens, and the owner holds every permission on it.
                if (vault.OwnerUserId == token.UserId)
                {
                    allowed.Add(vault.Id);
                }
            }
            else if (vault.TenantId == token.TenantId)
            {
                tenantVaults.Add(vault.Id);
            }
        }

        // The grant rule of IKeywardAccessPolicy for vaults, batched (TenantAuthorizationService owns it).
        allowed.UnionWith(await TenantAuthorizationService.VaultsWithGrantAsync(db, token.UserId, tenantVaults, permission, ct).ConfigureAwait(false));
        return allowed;
    }

    private async Task<bool> IsAllowedAsync(KeywardDbContext db, Guid tokenId, Guid vaultId, AgentScopes scope, Permission permission, CancellationToken ct)
    {
        var token = await db.AgentTokens.AsNoTracking()
            .FirstOrDefaultAsync(t => t.Id == tokenId, ct)
            .ConfigureAwait(false);
        if (token is null || !token.IsActive(clock.UtcNow) || !token.Allows(scope) || tenant.TenantId != token.TenantId)
        {
            return false;
        }

        // «All vaults opened to agents» replaces only the allowlist: the agent flag and the grant below still decide.
        var allowlisted = token.AllAgentVaults || await db.AgentTokenVaultAllowances.AsNoTracking()
            .AnyAsync(a => a.TokenId == tokenId && a.VaultId == vaultId, ct)
            .ConfigureAwait(false);
        if (!allowlisted)
        {
            return false;
        }

        // Through the tenant filter (and row-level security): another tenant's vault is simply not found.
        var vault = await db.Vaults.AsNoTracking()
            .Where(v => v.Id == vaultId)
            .Select(v => new { v.TenantId, v.OwnerUserId, v.AgentAccessAllowed, v.ProtectionMode })
            .FirstOrDefaultAsync(ct)
            .ConfigureAwait(false);
        if (vault is null || !vault.AgentAccessAllowed || vault.ProtectionMode != ProtectionMode.ServerSide)
        {
            return false;
        }

        // A personal vault (decision T12 B) is reachable only through its owner's tokens, whatever tenant they were
        // issued in; the owner holds every permission on it.
        if (vault.TenantId is null)
        {
            return vault.OwnerUserId == token.UserId;
        }

        if (vault.TenantId != token.TenantId)
        {
            return false;
        }

        return await authorization
            .IsAllowedAsync(token.UserId, new GrantScope(GrantScopeKind.Vault, vaultId), permission, ct)
            .ConfigureAwait(false);
    }
}
