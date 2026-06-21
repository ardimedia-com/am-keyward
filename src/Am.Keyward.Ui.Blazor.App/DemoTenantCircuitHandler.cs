using Am.Keyward.Core.Abstractions;
using Microsoft.AspNetCore.Components.Server.Circuits;

namespace Am.Keyward.Ui.Blazor.App;

/// <summary>
/// Demo-only: establishes the tenant scope for every Blazor circuit as the seeded demo tenant, so the
/// reference UI operates inside a tenant before a sign-in flow exists. Real authentication (a later slice)
/// sets the scope from the signed-in user's selected tenant instead of a fixed demo id.
/// </summary>
public sealed class DemoTenantCircuitHandler(ITenantScopeSetter tenantScope) : CircuitHandler
{
    public override Task OnCircuitOpenedAsync(Circuit circuit, CancellationToken cancellationToken)
    {
        tenantScope.SetTenant(Demo.TenantId);
        return Task.CompletedTask;
    }
}
