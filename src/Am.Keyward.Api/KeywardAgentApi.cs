using Am.Keyward.Contracts;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Am.Keyward.Api;

/// <summary>
/// The agent API: an AI assistant presents an agent token and works with vault items as the token's user,
/// narrowed by the token's scopes and vault allowlist (see <see cref="AgentAuthenticationHandler"/>). Every
/// vault or item endpoint decides access per request through <c>IAgentVaultAccess</c>.
/// </summary>
public static class KeywardAgentApi
{
    /// <summary>Rate-limiter policy name (registered by <c>AddKeywardAgentApi</c>), partitioned per token.</summary>
    public const string RateLimiterPolicy = "keyward-agent";

    /// <summary>Default base path of the agent endpoints.</summary>
    public const string DefaultPrefix = KeywardApiDefaults.BasePath + "/agent";

    public static IEndpointRouteBuilder MapKeywardAgentApi(this IEndpointRouteBuilder endpoints, string prefix = DefaultPrefix)
    {
        var group = endpoints.MapGroup(prefix)
            .WithTags("Keyward.Agent")
            .RequireAuthorization(AgentAuthenticationHandler.SchemeName)
            .RequireRateLimiting(RateLimiterPolicy)
            .DisableAntiforgery();

        // Reaching this line means the token authenticated and its user is still enabled and a tenant member —
        // lets a freshly issued token be checked by hand.
        group.MapGet("/ping", () => Results.NoContent());

        return endpoints;
    }
}
