using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Identity;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Am.Keyward.Infrastructure.Tenancy;

/// <summary>
/// The EF Core implementation of <see cref="IKeywardIdentityBinder"/>: finds or just-in-time creates the
/// <see cref="AppUser"/> for a host identity, keeps its flags in sync with the host's decision, and
/// reconciles the tenant membership.
/// <para>
/// The <c>Users</c> and <c>TenantMemberships</c> tables are installation-global (no tenant query filter), so
/// no tenant scope is required to run this — which matters, because it runs on the authentication path,
/// before any tenant scope exists.
/// </para>
/// <para>
/// Creation is serialized with a SQL application lock so that concurrent first-time sign-ins of the same
/// user cannot create duplicate rows; the filtered unique index on <c>ExternalId</c> is the backstop.
/// </para>
/// </summary>
internal sealed class KeywardIdentityBinder(KeywardDbContext db, IClock clock) : IKeywardIdentityBinder
{
    public async Task<KeywardBoundUser> BindAsync(
        string externalId,
        string displayName,
        Guid tenantId,
        KeywardIdentityBinding binding,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(externalId);

        AppUser user = await this.EnsureUserAsync(externalId, displayName, binding, cancellationToken).ConfigureAwait(false);
        await this.EnsureMembershipAsync(user, tenantId, binding, cancellationToken).ConfigureAwait(false);

        return new KeywardBoundUser(user.Id, user.IsSystemAdmin);
    }

    private async Task<AppUser> EnsureUserAsync(
        string externalId, string displayName, KeywardIdentityBinding binding, CancellationToken cancellationToken)
    {
        AppUser? existing = await this.FindAsync(externalId, cancellationToken).ConfigureAwait(false);
        if (existing is not null)
        {
            var changed = false;

            if (existing.IsSystemAdmin != binding.IsSystemAdmin)
            {
                if (binding.IsSystemAdmin) { existing.GrantSystemAdmin(); } else { existing.RevokeSystemAdmin(); }
                changed = true;
            }

            // A system admin administers everything, the software side included — so the effective flag is
            // the union, and a host that only sets IsSystemAdmin still gets a working software manager.
            var isSoftwareManager = binding.IsSoftwareManager || binding.IsSystemAdmin;
            if (existing.IsSoftwareManager != isSoftwareManager)
            {
                if (isSoftwareManager) { existing.GrantSoftwareManager(); } else { existing.RevokeSoftwareManager(); }
                changed = true;
            }

            if (changed)
            {
                await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            }

            return existing;
        }

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        await db.Database.ExecuteSqlRawAsync(
            "EXEC sp_getapplock @Resource = N'Keyward_UserInit', @LockMode = 'Exclusive', @LockOwner = 'Transaction';",
            cancellationToken).ConfigureAwait(false);

        existing = await this.FindAsync(externalId, cancellationToken).ConfigureAwait(false);
        if (existing is not null)
        {
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            return existing;
        }

        AppUser created = new(
            Guid.NewGuid(),
            issuer: null,
            externalId: externalId,
            displayName: string.IsNullOrWhiteSpace(displayName) ? externalId : displayName,
            isSystemAdmin: binding.IsSystemAdmin,
            createdAt: clock.UtcNow,
            isSoftwareManager: binding.IsSoftwareManager || binding.IsSystemAdmin);

        db.Users.Add(created);
        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return created;
    }

    /// <summary>
    /// A vault-capable user gets a membership (<see cref="TenantRole.TenantAdmin"/> for a system admin, else
    /// <see cref="TenantRole.Member"/>); a user the host says is NOT a tenant member gets none — and an
    /// existing one is REMOVED, so withdrawing vault access in the host actually withdraws it here.
    /// </summary>
    private async Task EnsureMembershipAsync(
        AppUser user, Guid tenantId, KeywardIdentityBinding binding, CancellationToken cancellationToken)
    {
        TenantMembership? membership = await db.TenantMemberships
            .FirstOrDefaultAsync(m => m.TenantId == tenantId && m.UserId == user.Id, cancellationToken)
            .ConfigureAwait(false);

        var isMember = binding.IsTenantMember || binding.IsSystemAdmin;
        if (!isMember)
        {
            if (membership is not null)
            {
                db.TenantMemberships.Remove(membership);
                await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            }

            return;
        }

        TenantRole role = binding.IsSystemAdmin ? TenantRole.TenantAdmin : TenantRole.Member;
        if (membership is null)
        {
            db.TenantMemberships.Add(new TenantMembership(Guid.NewGuid(), tenantId, user.Id, role, clock.UtcNow));
            try
            {
                await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (DbUpdateException)
            {
                // A concurrent sign-in of the same user inserted the row first; the unique (TenantId, UserId)
                // index makes this safe to ignore.
                db.ChangeTracker.Clear();
            }
        }
        else if (membership.Role != role)
        {
            membership.ChangeRole(role);
            await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private Task<AppUser?> FindAsync(string externalId, CancellationToken cancellationToken) =>
        db.Users.FirstOrDefaultAsync(u => u.Issuer == null && u.ExternalId == externalId, cancellationToken);
}
