using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.ValueObjects;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Am.Keyward.Infrastructure.Tenancy;

/// <summary>
/// The central authorization decision point. It resolves the resource's true owning tenant
/// (authoritatively, from the database) and confirms it matches the server-authoritative current tenant
/// — so a caller cannot reach another tenant's resource even if the query filter were bypassed.
/// v0.1 enforces tenant isolation only; fine-grained per-user / per-group <c>AccessGrant</c> evaluation
/// is layered in here when human vaults arrive, without changing the call sites.
/// </summary>
public sealed class TenantAuthorizationService(KeywardDbContext db, ICurrentTenant tenant) : IAuthorizationService
{
    public async ValueTask<bool> IsAllowedAsync(Guid? userId, GrantScope resource, Permission action, CancellationToken ct = default)
    {
        var current = tenant.TenantId;
        if (current is null)
        {
            return false; // No tenant scope established -> deny; system operations use an elevated path.
        }

        // Vaults are ACL-controlled within the tenant: access requires a grant to the user (group grants
        // are layered on later). Tenant isolation (filter + RLS) is the outer boundary; this is the refiner.
        if (resource.Kind == GrantScopeKind.Vault)
        {
            return userId is not null && await HasVaultGrantAsync(userId.Value, resource.TargetId, action, ct).ConfigureAwait(false);
        }

        // Projects/environments (software secrets): tenant-wide within the current tenant.
        var resourceTenant = await ResolveResourceTenantAsync(resource, ct).ConfigureAwait(false);
        return resourceTenant is not null && resourceTenant == current;
    }

    private async Task<bool> HasVaultGrantAsync(Guid userId, Guid vaultId, Permission action, CancellationToken ct)
    {
        // Permission is stored as a string, so compare the levels in memory (the set per user+vault is tiny).
        var permissions = await db.AccessGrants
            .Where(g => g.PrincipalType == PrincipalType.User
                     && g.PrincipalId == userId
                     && g.Scope.Kind == GrantScopeKind.Vault
                     && g.Scope.TargetId == vaultId)
            .Select(g => g.Permission)
            .ToListAsync(ct)
            .ConfigureAwait(false);

        return permissions.Any(p => p >= action);
    }

    private async Task<Guid?> ResolveResourceTenantAsync(GrantScope resource, CancellationToken ct) =>
        resource.Kind switch
        {
            GrantScopeKind.Project => await db.Projects.IgnoreQueryFilters()
                .Where(p => p.Id == resource.TargetId)
                .Select(p => (Guid?)p.TenantId)
                .FirstOrDefaultAsync(ct).ConfigureAwait(false),
            GrantScopeKind.Environment => await db.RuntimeEnvironments.IgnoreQueryFilters()
                .Where(e => e.Id == resource.TargetId)
                .Select(e => (Guid?)e.TenantId)
                .FirstOrDefaultAsync(ct).ConfigureAwait(false),
            _ => null, // Vault scope resolves once human vaults exist.
        };
}
