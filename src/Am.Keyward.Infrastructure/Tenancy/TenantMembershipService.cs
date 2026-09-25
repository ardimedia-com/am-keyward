using Am.Keyward.Core.Abstractions;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Am.Keyward.Infrastructure.Tenancy;

/// <summary>
/// Resolves whether an installation-global user may act within a tenant, from the <c>TenantMemberships</c>
/// table. System admins (the installation operators) are authorized for every tenant; any other user needs
/// an explicit membership row. A disabled user is a member of no tenant, whatever their flags and rows. Used at the host edge (see the management API) to gate the server-authoritative
/// tenant scope against a caller-supplied <c>{tenantId}</c>.
/// </summary>
public sealed class TenantMembershipService(IDbContextFactory<KeywardDbContext> dbFactory) : ITenantMembership
{
    public async ValueTask<bool> IsMemberAsync(Guid userId, Guid tenantId, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var user = await db.Users.AsNoTracking()
            .Where(u => u.Id == userId)
            .Select(u => new { u.IsSystemAdmin, u.DisabledAt })
            .FirstOrDefaultAsync(ct)
            .ConfigureAwait(false);

        if (user is null || user.DisabledAt is not null)
        {
            return false;
        }

        if (user.IsSystemAdmin)
        {
            return true;
        }

        return await db.TenantMemberships.AsNoTracking()
            .AnyAsync(m => m.UserId == userId && m.TenantId == tenantId, ct)
            .ConfigureAwait(false);
    }
}
