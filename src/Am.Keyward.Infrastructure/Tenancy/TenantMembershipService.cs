using Am.Keyward.Core.Abstractions;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Am.Keyward.Infrastructure.Tenancy;

/// <summary>
/// Resolves whether an installation-global user may act within a tenant, from the <c>TenantMemberships</c>
/// table. System admins (the installation operators) are authorized for every tenant; any other user needs
/// an explicit membership row. Used at the host edge (see the management API) to gate the server-authoritative
/// tenant scope against a caller-supplied <c>{tenantId}</c>.
/// </summary>
public sealed class TenantMembershipService(KeywardDbContext db) : ITenantMembership
{
    public async ValueTask<bool> IsMemberAsync(Guid userId, Guid tenantId, CancellationToken ct = default)
    {
        if (await db.Users.AsNoTracking()
            .AnyAsync(u => u.Id == userId && u.IsSystemAdmin, ct)
            .ConfigureAwait(false))
        {
            return true;
        }

        return await db.TenantMemberships.AsNoTracking()
            .AnyAsync(m => m.UserId == userId && m.TenantId == tenantId, ct)
            .ConfigureAwait(false);
    }
}
