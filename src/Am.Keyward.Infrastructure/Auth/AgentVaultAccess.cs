using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Agent;
using Am.Keyward.Core.Domain.ValueObjects;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Am.Keyward.Infrastructure.Auth;

/// <summary>
/// The single authorization decision for agent requests, made on every request from the current database state:
/// clearing a vault's agent flag, dropping it from the allowlist, revoking the user's grant or the token itself
/// takes effect on the next call. Must run in the token's tenant scope (the agent handler sets it).
/// </summary>
public sealed class AgentVaultAccess(
    IDbContextFactory<KeywardDbContext> dbFactory,
    IClock clock,
    ICurrentTenant tenant,
    IKeywardAccessPolicy authorization) : IAgentVaultAccess
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

    private async Task<bool> IsAllowedAsync(KeywardDbContext db, Guid tokenId, Guid vaultId, AgentScopes scope, Permission permission, CancellationToken ct)
    {
        var token = await db.AgentTokens.AsNoTracking()
            .FirstOrDefaultAsync(t => t.Id == tokenId, ct)
            .ConfigureAwait(false);
        if (token is null || !token.IsActive(clock.UtcNow) || !token.Allows(scope) || tenant.TenantId != token.TenantId)
        {
            return false;
        }

        var allowlisted = await db.AgentTokenVaultAllowances.AsNoTracking()
            .AnyAsync(a => a.TokenId == tokenId && a.VaultId == vaultId, ct)
            .ConfigureAwait(false);
        if (!allowlisted)
        {
            return false;
        }

        // Through the tenant filter (and row-level security): another tenant's vault is simply not found.
        var vault = await db.Vaults.AsNoTracking()
            .Where(v => v.Id == vaultId)
            .Select(v => new { v.TenantId, v.AgentAccessAllowed, v.ProtectionMode })
            .FirstOrDefaultAsync(ct)
            .ConfigureAwait(false);
        if (vault is null || vault.TenantId != token.TenantId || !vault.AgentAccessAllowed || vault.ProtectionMode != ProtectionMode.ServerSide)
        {
            return false;
        }

        return await authorization
            .IsAllowedAsync(token.UserId, new GrantScope(GrantScopeKind.Vault, vaultId), permission, ct)
            .ConfigureAwait(false);
    }
}
