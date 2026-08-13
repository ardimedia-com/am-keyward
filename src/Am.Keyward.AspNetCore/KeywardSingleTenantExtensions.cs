using System.Security.Claims;
using Am.Keyward.Core.Abstractions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Components.Server.Circuits;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Am.Keyward.AspNetCore;

/// <summary>
/// Hosting glue for a <b>single-organization</b> host: an application whose users all belong to one fixed
/// Keyward tenant, so there is no per-request tenant selection to make. It supplies the three pieces such a
/// host would otherwise hand-write every time — the workspace context the UI reads, the circuit handler that
/// pins the tenant on the interactive path, and the middleware that pins it on the HTTP/SSR path.
/// <para>
/// A multi-tenant host does NOT use this: it implements <see cref="IKeywardWorkspaceContext"/> from its own
/// tenant selection and calls <see cref="ITenantScopeSetter.SetTenant"/> accordingly.
/// </para>
/// </summary>
public static class KeywardSingleTenantExtensions
{
    /// <summary>
    /// Registers the fixed-tenant workspace context (what the embedded UI pages read) and a circuit handler
    /// that establishes the tenant scope when a Blazor circuit opens. Pair it with
    /// <see cref="UseKeywardSingleTenant"/>, which covers the HTTP/SSR path, and with
    /// <c>AddKeywardBlazorUserScope</c>, which establishes the current USER on the circuit.
    /// <para>
    /// Without a tenant scope on the circuit every Keyward page fails with "Tenant scope mismatch".
    /// </para>
    /// </summary>
    /// <param name="tenantId">The host's single tenant — a stable constant, the same one it seeds.</param>
    public static IServiceCollection AddKeywardSingleTenant(this IServiceCollection services, Guid tenantId)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddSingleton<IKeywardWorkspaceContext>(new FixedTenantWorkspaceContext(tenantId));
        services.AddScoped<CircuitHandler>(sp =>
            new SingleTenantCircuitHandler(sp.GetRequiredService<ITenantScopeSetter>(), tenantId));
        return services;
    }

    /// <summary>
    /// Pins the single tenant on the HTTP/SSR request path. Required in addition to the circuit handler: a
    /// Keyward page that PRERENDERS calls a Keyward service during <c>OnInitializedAsync</c> BEFORE the
    /// circuit is open, and would otherwise hit an unset ambient tenant ("Tenant scope mismatch").
    /// <para>Add it after <c>UseAuthentication()</c> / <c>UseAuthorization()</c>, next to
    /// <c>UseKeywardCurrentUser()</c>.</para>
    /// </summary>
    public static IApplicationBuilder UseKeywardSingleTenant(this IApplicationBuilder app, Guid tenantId)
    {
        ArgumentNullException.ThrowIfNull(app);

        return app.Use(async (context, next) =>
        {
            context.RequestServices.GetService<ITenantScopeSetter>()?.SetTenant(tenantId);
            await next();
        });
    }

    private sealed class FixedTenantWorkspaceContext(Guid tenantId) : IKeywardWorkspaceContext
    {
        public Guid TenantId { get; } = tenantId;
    }

    private sealed class SingleTenantCircuitHandler(ITenantScopeSetter tenantScope, Guid tenantId) : CircuitHandler
    {
        public override Task OnCircuitOpenedAsync(Circuit circuit, CancellationToken cancellationToken)
        {
            tenantScope.SetTenant(tenantId);
            return Task.CompletedTask;
        }
    }
}

/// <summary>
/// The host side of Keyward's identity binding, for an ASP.NET Core host that stamps Keyward's claims onto
/// the signed-in principal (typically from a <c>UserClaimsPrincipalFactory</c>).
/// <para>
/// It takes the one decision that is genuinely the host's — what this user may be, as a
/// <see cref="KeywardIdentityBinding"/> derived from the host's own roles — and does everything that is the
/// same everywhere: run the binder, stamp <see cref="KeywardClaims.UserId"/> and
/// <see cref="KeywardClaims.SystemAdmin"/>, and treat a Keyward outage as non-fatal.
/// </para>
/// </summary>
public static class KeywardClaimsBinding
{
    /// <summary>
    /// Binds the identity and stamps Keyward's claims onto it. Returns the bound user, or <c>null</c> when
    /// nothing was bound — either because the binding grants nothing, or because Keyward is unavailable.
    /// <para>
    /// <b>Best-effort by design.</b> This runs on the AUTHENTICATION path: if Keyward is not provisioned in
    /// this environment (database unreachable, schema missing), throwing here would break authentication —
    /// and therefore every page — for every user of the host application. Instead the failure is logged and
    /// the identity is returned without Keyward's claims, so the user stays signed in and only the Keyward
    /// pages are unavailable until Keyward is provisioned.
    /// </para>
    /// </summary>
    /// <param name="identity">The identity being built; claims are added to it.</param>
    /// <param name="binder">Resolved from DI (registered by <c>AddKeyward</c>).</param>
    /// <param name="externalId">The host's stable user id for this person.</param>
    /// <param name="displayName">Shown in Keyward's UI; only used when the user is created.</param>
    /// <param name="tenantId">The tenant whose membership is reconciled (the single tenant, for such a host).</param>
    /// <param name="binding">What the host decided this user may be.</param>
    /// <param name="logger">Where a binding failure is reported.</param>
    public static async Task<KeywardBoundUser?> ApplyAsync(
        ClaimsIdentity identity,
        IKeywardIdentityBinder binder,
        string externalId,
        string displayName,
        Guid tenantId,
        KeywardIdentityBinding binding,
        ILogger logger,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(binder);
        ArgumentNullException.ThrowIfNull(logger);

        // A user the host grants nothing gets no Keyward identity at all: no user-id claim, so no Keyward
        // user scope is ever established for them and every Keyward service call fails its scope check.
        if (!binding.GrantsAnything)
        {
            return null;
        }

        try
        {
            KeywardBoundUser bound = await binder
                .BindAsync(externalId, displayName, tenantId, binding, cancellationToken)
                .ConfigureAwait(false);

            identity.AddClaim(new Claim(KeywardClaims.UserId, bound.UserId.ToString()));
            if (bound.IsSystemAdmin)
            {
                identity.AddClaim(new Claim(KeywardClaims.SystemAdmin, "true"));
            }

            return bound;
        }
        catch (Exception ex)
        {
            logger.LogError(ex,
                "KEYWARD: could not bind the Keyward identity for external user {ExternalId} — Keyward is "
                + "unavailable in this environment (not provisioned; database unreachable or schema missing). "
                + "The user stays signed in; Keyward pages will not work until Keyward is provisioned.",
                externalId);
            return null;
        }
    }
}
