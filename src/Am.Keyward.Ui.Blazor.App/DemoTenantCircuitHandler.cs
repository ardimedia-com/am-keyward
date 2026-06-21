using System.Security.Claims;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Ui.Blazor.App.Identity;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server.Circuits;

namespace Am.Keyward.Ui.Blazor.App;

/// <summary>
/// Establishes the server-authoritative scope for every Blazor circuit: the demo tenant (sign-in
/// identifies the user, not the tenant yet) and the signed-in user (from the circuit's authentication
/// state, for personal-vault isolation). Real multi-tenant selection replaces the fixed demo tenant later.
/// </summary>
public sealed class DemoTenantCircuitHandler(
    ITenantScopeSetter tenantScope,
    IUserScopeSetter userScope,
    AuthenticationStateProvider authenticationStateProvider) : CircuitHandler
{
    public override async Task OnCircuitOpenedAsync(Circuit circuit, CancellationToken cancellationToken)
    {
        tenantScope.SetTenant(Demo.TenantId);

        var state = await authenticationStateProvider.GetAuthenticationStateAsync();
        if (Guid.TryParse(state.User.FindFirst(KeywardUserClaimsPrincipalFactory.UserIdClaim)?.Value, out var userId))
        {
            userScope.SetUser(userId);
        }
    }
}
