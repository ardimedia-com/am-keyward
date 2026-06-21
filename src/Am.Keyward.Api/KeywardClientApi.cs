using System.Security.Claims;
using Am.Keyward.Core.Application;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Am.Keyward.Api;

/// <summary>
/// The software-client read API: a deployed application presents its Bearer token and reads only the
/// secrets of the token's (project, environment). The scope comes entirely from the authenticated token
/// (see <see cref="SoftwareClientAuthenticationHandler"/>); the client supplies no tenant/project/env.
/// </summary>
public static class KeywardClientApi
{
    /// <summary>Rate-limiter policy name (registered by <c>AddKeywardSoftwareClientApi</c>), partitioned per token.</summary>
    public const string RateLimiterPolicy = "keyward-software-client";

    public static IEndpointRouteBuilder MapKeywardClientApi(this IEndpointRouteBuilder endpoints, string prefix = "/keyward/api/v1")
    {
        var group = endpoints.MapGroup(prefix)
            .WithTags("Keyward.SoftwareClient")
            .RequireAuthorization(SoftwareClientAuthenticationHandler.SchemeName)
            .RequireRateLimiting(RateLimiterPolicy)
            .DisableAntiforgery();

        // Bulk load — all current key/value pairs for the token's environment (feeds IConfiguration).
        group.MapGet("/secrets", async (ClaimsPrincipal user, ISoftwareSecretReader reader, CancellationToken ct) =>
        {
            var (tenantId, projectId, environmentId) = ReadScope(user);
            var all = await reader.ReadAllAsync(tenantId, projectId, environmentId, null, ct);
            return Results.Ok(all.ToDictionary(kv => kv.Key, kv => kv.Value));
        });

        // Single secret by key.
        group.MapGet("/secrets/{**key}", async (string key, ClaimsPrincipal user, ISoftwareSecretReader reader, CancellationToken ct) =>
        {
            var (tenantId, projectId, environmentId) = ReadScope(user);
            var value = await reader.ReadAsync(tenantId, projectId, environmentId, key, null, ct);
            return value is null ? Results.NotFound() : Results.Ok(new KeywardApi.SecretResponse(key, value));
        });

        return endpoints;
    }

    private static (Guid TenantId, Guid ProjectId, Guid EnvironmentId) ReadScope(ClaimsPrincipal user) =>
    (
        Guid.Parse(user.FindFirstValue(SoftwareClientAuthenticationHandler.TenantIdClaim)!),
        Guid.Parse(user.FindFirstValue(SoftwareClientAuthenticationHandler.ProjectIdClaim)!),
        Guid.Parse(user.FindFirstValue(SoftwareClientAuthenticationHandler.EnvironmentIdClaim)!)
    );
}
