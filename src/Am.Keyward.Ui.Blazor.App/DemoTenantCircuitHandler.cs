using Am.Keyward.Core.Abstractions;
using Microsoft.AspNetCore.Components.Server.Circuits;

namespace Am.Keyward.Ui.Blazor.App;

/// <summary>
/// Establishes the server-authoritative tenant for every Blazor circuit: the fixed demo tenant (sign-in
/// identifies the user, not the tenant yet). The per-circuit USER scope is established separately by the
/// reusable <c>KeywardUserCircuitHandler</c> (registered via <c>AddKeywardBlazorUserScope</c>). Real
/// multi-tenant selection replaces this fixed demo tenant later.
/// </summary>
public sealed class DemoTenantCircuitHandler(ITenantScopeSetter tenantScope) : CircuitHandler
{
    public override Task OnCircuitOpenedAsync(Circuit circuit, CancellationToken cancellationToken)
    {
        tenantScope.SetTenant(Demo.TenantId);
        return Task.CompletedTask;
    }
}
