using System.Security.Claims;
using Am.Keyward.AspNetCore;
using Am.Keyward.Core.Abstractions;
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
        identity.AddClaim(new Claim(KeywardClaims.UserId, appUser.Id.ToString()));
        if (appUser.IsSystemAdmin)
        {
            identity.AddClaim(new Claim(KeywardClaims.SystemAdmin, "true"));
        }

        return identity;
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
