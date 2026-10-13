using System.Security.Claims;
using Am.Keyward.Contracts;
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

    public static IEndpointRouteBuilder MapKeywardClientApi(this IEndpointRouteBuilder endpoints, string prefix = KeywardApiDefaults.BasePath)
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
            var all = await reader.ReadAllAsync(tenantId, projectId, environmentId, ct);
            return Results.Ok(all.ToDictionary(kv => kv.Key, kv => kv.Value));
        });

        // Single secret by key. A 404 says why — an unknown key or no value in this environment — as `reason`
        // (KeywardApiDefaults.UnknownKeyReason / NoValueReason), so a script can fail with the cause.
        group.MapGet("/secrets/{**key}", async (string key, ClaimsPrincipal user, ISoftwareSecretReader reader, CancellationToken ct) =>
        {
            var (tenantId, projectId, environmentId) = ReadScope(user);
            var audit = user.HasClaim(SoftwareClientAuthenticationHandler.AuditReadsClaim, "true");
            var outcome = await reader.ReadOneAsync(tenantId, projectId, environmentId, key, audit, ct);
            return outcome.Status switch
            {
                SecretReadStatus.Found => Results.Ok(new SecretResponse(key, outcome.Value!)),
                SecretReadStatus.NoValue => Results.Problem(statusCode: StatusCodes.Status404NotFound,
                    title: "The key has no value in this environment.",
                    extensions: new Dictionary<string, object?> { ["reason"] = KeywardApiDefaults.NoValueReason }),
                _ => Results.Problem(statusCode: StatusCodes.Status404NotFound,
                    title: "The application has no such key.",
                    extensions: new Dictionary<string, object?> { ["reason"] = KeywardApiDefaults.UnknownKeyReason }),
            };
        });

        // Explicit heartbeat. Reaching this line means the token authenticated, and the authentication
        // handler already recorded the access — a ping IS a token access, so it feeds the statistics and
        // heartbeat monitoring without any extra machinery. For long-running services that read their
        // secrets only at startup: ping periodically to keep the silence monitor fed.
        group.MapGet("/ping", () => Results.NoContent());

        return endpoints;
    }

    private static (Guid TenantId, Guid ProjectId, Guid EnvironmentId) ReadScope(ClaimsPrincipal user) =>
    (
        Guid.Parse(user.FindFirstValue(SoftwareClientAuthenticationHandler.TenantIdClaim)!),
        Guid.Parse(user.FindFirstValue(SoftwareClientAuthenticationHandler.ProjectIdClaim)!),
        Guid.Parse(user.FindFirstValue(SoftwareClientAuthenticationHandler.EnvironmentIdClaim)!)
    );
}
