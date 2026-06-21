using System.Security.Claims;
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
    public const string UserIdClaim = "keyward:user_id";
    public const string SystemAdminClaim = "keyward:is_system_admin";

    protected override async Task<ClaimsIdentity> GenerateClaimsAsync(IdentityUser user)
    {
        var identity = await base.GenerateClaimsAsync(user);

        var appUser = await EnsureAppUserAsync(user);
        identity.AddClaim(new Claim(UserIdClaim, appUser.Id.ToString()));
        if (appUser.IsSystemAdmin)
        {
            identity.AddClaim(new Claim(SystemAdminClaim, "true"));
        }

        return identity;
    }

    private async Task<AppUser> EnsureAppUserAsync(IdentityUser user)
    {
        // The Users table is installation-global (no tenant filter), so no tenant scope is needed here.
        var existing = await db.Users.FirstOrDefaultAsync(u => u.Issuer == null && u.ExternalId == user.Id);
        if (existing is not null)
        {
            return existing;
        }

        var isFirstUser = !await db.Users.AnyAsync();
        var appUser = new AppUser(
            Guid.NewGuid(), issuer: null, externalId: user.Id,
            displayName: user.UserName ?? user.Email ?? user.Id,
            isSystemAdmin: isFirstUser, createdAt: clock.UtcNow);

        db.Users.Add(appUser);
        await db.SaveChangesAsync();
        return appUser;
    }
}
