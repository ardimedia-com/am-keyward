using System.Security.Claims;
using Am.Keyward.Core.Abstractions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server.Circuits;
using Microsoft.Extensions.DependencyInjection;

namespace Am.Keyward.AspNetCore;

/// <summary>
/// Wires the signed-in principal into AM KEYWARD's server-authoritative current user, on both request paths:
/// the HTTP middleware (<see cref="UseKeywardCurrentUser"/>) and the Blazor Server circuit
/// (<see cref="AddKeywardBlazorUserScope"/>). Both read <see cref="KeywardClaims.UserId"/> and call
/// <see cref="IUserScopeSetter"/>; TENANT selection stays the host's own concern.
/// </summary>
public static class KeywardHostingExtensions
{
    /// <summary>
    /// Establishes the server-authoritative current user for each HTTP request from the
    /// <see cref="KeywardClaims.UserId"/> claim on the authenticated principal (drives personal-vault
    /// isolation). Add it AFTER <c>UseAuthentication()</c>/<c>UseAuthorization()</c>. The Blazor circuit path
    /// issues no cookie-bearing HTTP requests, so it is covered separately by
    /// <see cref="AddKeywardBlazorUserScope"/>.
    /// </summary>
    public static IApplicationBuilder UseKeywardCurrentUser(this IApplicationBuilder app) =>
        app.Use(async (context, next) =>
        {
            if (TryReadUserId(context.User, out var userId))
            {
                context.RequestServices.GetRequiredService<IUserScopeSetter>().SetUser(userId);
            }

            await next();
        });

    /// <summary>
    /// Registers a Blazor Server circuit handler that establishes the current user (from the circuit's
    /// authentication state) when the circuit opens — the SignalR counterpart to
    /// <see cref="UseKeywardCurrentUser"/>. Register your own <c>CircuitHandler</c> for tenant selection.
    /// </summary>
    public static IServiceCollection AddKeywardBlazorUserScope(this IServiceCollection services)
    {
        services.AddScoped<CircuitHandler, KeywardUserCircuitHandler>();
        return services;
    }

    internal static bool TryReadUserId(ClaimsPrincipal principal, out Guid userId) =>
        Guid.TryParse(principal.FindFirst(KeywardClaims.UserId)?.Value, out userId);
}

/// <summary>
/// Establishes the server-authoritative current user for a Blazor Server circuit from its authentication
/// state on circuit open (personal-vault isolation). Tenant selection is a separate, host-owned concern.
/// </summary>
internal sealed class KeywardUserCircuitHandler(
    IUserScopeSetter userScope,
    AuthenticationStateProvider authenticationStateProvider) : CircuitHandler
{
    public override async Task OnCircuitOpenedAsync(Circuit circuit, CancellationToken cancellationToken)
    {
        var state = await authenticationStateProvider.GetAuthenticationStateAsync().ConfigureAwait(false);
        if (KeywardHostingExtensions.TryReadUserId(state.User, out var userId))
        {
            userScope.SetUser(userId);
        }
    }
}
