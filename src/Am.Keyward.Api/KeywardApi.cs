using Am.Keyward.Core.Application;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

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
