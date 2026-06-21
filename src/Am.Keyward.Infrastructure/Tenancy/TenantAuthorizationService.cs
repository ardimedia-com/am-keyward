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

        var resourceTenant = await ResolveResourceTenantAsync(resource, ct).ConfigureAwait(false);
        return resourceTenant is not null && resourceTenant == current;
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
