using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Am.Keyward.Api;

public static class KeywardApi
{
    /// <summary>
    /// Maps the software-credentials API under <paramref name="prefix"/> (versioned). Walking-skeleton
    /// scope: these endpoints are UNAUTHENTICATED — software-client token auth, server-authoritative
    /// tenant binding and rate limiting arrive in Slice 5. Do not expose this build publicly.
    /// </summary>
    public static IEndpointRouteBuilder MapKeywardApi(this IEndpointRouteBuilder endpoints, string prefix = "/keyward/api/v1")
    {
        var group = endpoints.MapGroup(prefix).WithTags("Keyward").DisableAntiforgery();

        // Establish the server-authoritative tenant scope from the route's {tenantId} (the first route
        // argument on every endpoint here), so the query filter and row-level security apply. Interim:
        // Slice 5 derives the tenant from the software-client token and verifies it matches the route.
        group.AddEndpointFilter(async (context, next) =>
        {
            var tenantId = context.GetArgument<Guid>(0);
            context.HttpContext.RequestServices.GetRequiredService<ITenantScopeSetter>().SetTenant(tenantId);
            return await next(context);
        });

        group.MapPut(
            "/tenants/{tenantId:guid}/projects/{projectId:guid}/environments/{environment}/secrets/{**key}",
            async (Guid tenantId, Guid projectId, string environment, string key, StoreSecretRequest body, ISoftwareSecretService service, CancellationToken ct) =>
            {
                await service.StoreAsync(new StoreSoftwareSecretCommand(tenantId, projectId, environment, key, body.Value, null), ct);
                return Results.NoContent();
            });

        group.MapGet(
            "/tenants/{tenantId:guid}/projects/{projectId:guid}/environments/{environment}/secrets/{**key}",
            async (Guid tenantId, Guid projectId, string environment, string key, ISoftwareSecretService service, CancellationToken ct) =>
            {
                var value = await service.ReadAsync(new ReadSoftwareSecretQuery(tenantId, projectId, environment, key, null), ct);
                return value is null ? Results.NotFound() : Results.Ok(new SecretResponse(key, value));
            });

        return endpoints;
    }

    public sealed record StoreSecretRequest(string Value);

    public sealed record SecretResponse(string Key, string Value);
}
