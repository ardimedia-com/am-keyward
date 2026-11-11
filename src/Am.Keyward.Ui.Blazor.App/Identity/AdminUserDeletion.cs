using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Domain;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Am.Keyward.Ui.Blazor.App.Identity;

/// <summary>What <see cref="AdminUserDeletion.DeleteAsync"/> did.</summary>
public enum AdminUserDeletionOutcome
{
    /// <summary>Nothing done: the acting admin themself, or the last tenant / system admin.</summary>
    Refused,

    /// <summary>No such user.</summary>
    NotFound,

    /// <summary>The account never signed in (no Keyward user, e.g. an unaccepted invitation): its login was deleted.</summary>
    LoginDeleted,

    /// <summary>
    /// The account is deleted with retention: login locked for good and sessions ended, Keyward user disabled, agent
    /// tokens revoked, personal vaults kept until the retention period has passed.
    /// </summary>
    AccountDeleted,
}

/// <summary>
/// The reference shell's «delete user» (offboarding), on top of <see cref="IKeywardAccountDeletion"/>: the user is
/// disabled at once and their personal vaults are kept for the retention period (<c>Keyward:Retention</c>, 90 days)
/// before the retention job removes them; until then «Enable» restores the account with its vaults. So the Identity
/// login is NOT deleted — it is locked for good and its security stamp rotated, which ends every running session.
/// Memberships and access grants stay (a disabled user counts as a member of no tenant); team vaults belong to the
/// tenant and are never touched; the domain user row stays for the audit chain's actor references. An account that
/// never signed in holds nothing to retain, so its login is deleted outright.
/// </summary>
public sealed class AdminUserDeletion(
    UserManager<IdentityUser> users,
    KeywardDbContext db,
    IKeywardAccountDeletion accountDeletion)
{
    /// <param name="targetUserId">The Identity user id of the account to delete.</param>
    /// <param name="actingUserId">The Identity user id of the acting admin (never deletes themself).</param>
    /// <param name="tenantId">The tenant whose last admin must stay.</param>
    /// <param name="auditAsync">Records the admin's action; runs once the guards passed, before anything changes.</param>
    /// <param name="ct">Cancellation.</param>
    public async Task<AdminUserDeletionOutcome> DeleteAsync(
        string targetUserId, string? actingUserId, Guid tenantId, Func<Task> auditAsync, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(targetUserId);
        ArgumentNullException.ThrowIfNull(auditAsync);

        if (targetUserId == actingUserId)
        {
            return AdminUserDeletionOutcome.Refused;
        }

        var domainUser = await db.Users.FirstOrDefaultAsync(u => u.Issuer == null && u.ExternalId == targetUserId, ct);
        if (domainUser is not null)
        {
            var isLastSystemAdmin = domainUser.IsSystemAdmin
                && await db.Users.CountAsync(u => u.IsSystemAdmin, ct) <= 1;
            var isLastTenantAdmin = await db.TenantMemberships.AnyAsync(m =>
                    m.TenantId == tenantId && m.UserId == domainUser.Id && m.Role == TenantRole.TenantAdmin, ct)
                && await db.TenantMemberships.CountAsync(m =>
                    m.TenantId == tenantId && m.Role == TenantRole.TenantAdmin, ct) <= 1;
            if (isLastSystemAdmin || isLastTenantAdmin)
            {
                return AdminUserDeletionOutcome.Refused;
            }
        }

        var identityUser = await users.FindByIdAsync(targetUserId);
        if (domainUser is null && identityUser is null)
        {
            return AdminUserDeletionOutcome.NotFound;
        }

        await auditAsync();

        if (domainUser is null)
        {
            await users.DeleteAsync(identityUser!);
            return AdminUserDeletionOutcome.LoginDeleted;
        }

        if (identityUser is not null)
        {
            // Like «disable»: no new sign-in, and the rotated stamp ends the running sessions (cookie re-validation and
            // the circuit's revalidating auth-state provider both compare it).
            await users.SetLockoutEnabledAsync(identityUser, true);
            await users.SetLockoutEndDateAsync(identityUser, DateTimeOffset.MaxValue);
            await users.UpdateSecurityStampAsync(identityUser);
        }

        // Disables the Keyward user, revokes their agent tokens and starts the personal-vault retention (audited).
        await accountDeletion.DeleteAccountAsync(targetUserId, ct);
        return AdminUserDeletionOutcome.AccountDeleted;
    }
}
