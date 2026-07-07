using System.Security.Claims;
using Am.Keyward.AspNetCore;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Identity;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Am.Keyward.Ui.Blazor.App.Identity;

/// <summary>
/// Maps the signed-in Identity user to the domain <see cref="AppUser"/> (created just-in-time, keyed by
/// the Identity user id) and stamps the resulting claims into the auth cookie, so both API requests and
/// Blazor circuits can read the Keyward user id. The FIRST account ever created becomes the System Admin.
/// </summary>
public sealed class KeywardUserClaimsPrincipalFactory(
    UserManager<IdentityUser> userManager,
    IOptions<IdentityOptions> optionsAccessor,
    KeywardDbContext db,
    IClock clock) : UserClaimsPrincipalFactory<IdentityUser>(userManager, optionsAccessor)
{
    protected override async Task<ClaimsIdentity> GenerateClaimsAsync(IdentityUser user)
    {
        var identity = await base.GenerateClaimsAsync(user);

        var appUser = await EnsureAppUserAsync(user);
        await EnsureTenantMembershipAsync(appUser);
        identity.AddClaim(new Claim(KeywardClaims.UserId, appUser.Id.ToString()));
        if (appUser.IsSystemAdmin)
        {
            identity.AddClaim(new Claim(KeywardClaims.SystemAdmin, "true"));
        }

        return identity;
    }

    /// <summary>
    /// Every UI user of the reference shell belongs to the demo tenant (a real host assigns memberships
    /// from its own tenant model). Membership is what scopes tenant-facing lists (e.g. vault share
    /// candidates), so it is ensured for existing users too — a backfill on their next sign-in.
    /// TenantMemberships is installation-global (no tenant query filter / RLS), so no tenant scope is
    /// needed here.
    /// </summary>
    private async Task EnsureTenantMembershipAsync(AppUser appUser)
    {
        if (await db.TenantMemberships.AnyAsync(m => m.TenantId == Demo.TenantId && m.UserId == appUser.Id))
        {
            return;
        }

        var role = appUser.IsSystemAdmin ? TenantRole.TenantAdmin : TenantRole.Member;
        db.TenantMemberships.Add(new TenantMembership(Guid.NewGuid(), Demo.TenantId, appUser.Id, role, clock.UtcNow));
        try
        {
            await db.SaveChangesAsync();
        }
        catch (DbUpdateException)
        {
            // A concurrent sign-in of the same user inserted the row first; the unique (TenantId, UserId)
            // index makes this safe to ignore.
            db.ChangeTracker.Clear();
        }
    }

    private async Task<AppUser> EnsureAppUserAsync(IdentityUser user)
    {
        // The Users table is installation-global (no tenant filter), so no tenant scope is needed here.
        var existing = await FindLocalUserAsync(user.Id);
        if (existing is not null)
        {
            return existing;
        }

        // Serialize the just-in-time creation across concurrent sign-ins with a SQL app-lock, so the
        // "first account becomes the System Admin" decision and the insert are atomic: two simultaneous
        // first-time sign-ins can neither both become admin nor create duplicate rows for the same user.
        // The filtered unique index on ExternalId is the database backstop if the lock is ever unavailable.
        await using var tx = await db.Database.BeginTransactionAsync();
        await db.Database.ExecuteSqlRawAsync(
            "EXEC sp_getapplock @Resource = N'Keyward_UserInit', @LockMode = 'Exclusive', @LockOwner = 'Transaction';");

        // Re-check inside the lock — another concurrent sign-in for this user may have created it.
        existing = await FindLocalUserAsync(user.Id);
        if (existing is not null)
        {
            await tx.CommitAsync();
            return existing;
        }

        var isFirstUser = !await db.Users.AnyAsync();
        var appUser = new AppUser(
            Guid.NewGuid(), issuer: null, externalId: user.Id,
            displayName: user.UserName ?? user.Email ?? user.Id,
            isSystemAdmin: isFirstUser, createdAt: clock.UtcNow);

        db.Users.Add(appUser);
        await db.SaveChangesAsync();
        await tx.CommitAsync();
        return appUser;
    }

    private Task<AppUser?> FindLocalUserAsync(string externalId) =>
        db.Users.FirstOrDefaultAsync(u => u.Issuer == null && u.ExternalId == externalId);
}
