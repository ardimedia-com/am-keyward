using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace Am.Keyward.Ui.Blazor.App.Identity;

/// <summary>
/// Re-checks the user of a live Blazor circuit every <see cref="RevalidationInterval"/>: an account that was
/// deleted, disabled (or locked) or whose security stamp changed (password reset, admin disable) loses its
/// session in the open tab too, not only on the next HTTP request. The cookie side is covered by
/// <c>SecurityStampValidatorOptions.ValidationInterval</c>.
/// </summary>
public sealed class IdentityRevalidatingAuthenticationStateProvider(
    ILoggerFactory loggerFactory,
    IServiceScopeFactory scopeFactory,
    IOptions<IdentityOptions> options) : RevalidatingServerAuthenticationStateProvider(loggerFactory)
{
    protected override TimeSpan RevalidationInterval => TimeSpan.FromMinutes(10);

    protected override async Task<bool> ValidateAuthenticationStateAsync(
        AuthenticationState authenticationState, CancellationToken cancellationToken)
    {
        await using var scope = scopeFactory.CreateAsyncScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
        return await IsStillValidAsync(userManager, options.Value, authenticationState.User);
    }

    /// <summary>Whether <paramref name="principal"/> still belongs to an existing, unlocked user with the same security stamp.</summary>
    public static async Task<bool> IsStillValidAsync(UserManager<IdentityUser> userManager, IdentityOptions options, ClaimsPrincipal principal)
    {
        var user = await userManager.GetUserAsync(principal);
        if (user is null || await userManager.IsLockedOutAsync(user))
        {
            return false;
        }

        if (!userManager.SupportsUserSecurityStamp)
        {
            return true;
        }

        var principalStamp = principal.FindFirstValue(options.ClaimsIdentity.SecurityStampClaimType);
        var userStamp = await userManager.GetSecurityStampAsync(user);
        return principalStamp == userStamp;
    }
}
