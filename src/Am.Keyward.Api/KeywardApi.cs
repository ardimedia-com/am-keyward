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
    /// Maps the management/admin API under <paramref name="prefix"/> (versioned): create/read secrets and
    /// manage software-client tokens. The tenant scope is taken server-authoritatively from the route's
    /// {tenantId}. Pass <paramref name="authorizationPolicy"/> to require a signed-in admin (the reference
    /// shell does). (The software CLIENT read path is token-authenticated; see
    /// <see cref="KeywardClientApi.MapKeywardClientApi"/>.)
    /// </summary>
    public static IEndpointRouteBuilder MapKeywardApi(
        this IEndpointRouteBuilder endpoints, string prefix = "/keyward/api/v1", string? authorizationPolicy = null)
    {
        var group = endpoints.MapGroup(prefix).WithTags("Keyward").DisableAntiforgery();

        if (authorizationPolicy is not null)
        {
            group.RequireAuthorization(authorizationPolicy);
        }

        // Gate the caller-supplied route {tenantId} against the signed-in user's tenant membership, THEN
        // establish the server-authoritative tenant scope from it (so the query filter and row-level security
        // apply). Without the membership check any authenticated user could target any tenant's secrets/tokens
        // by putting that tenant's id in the route. The user is resolved by the host from the auth cookie
        // (see ICurrentUser); system admins are members of every tenant.
        group.AddEndpointFilter(async (context, next) =>
        {
            var tenantId = context.GetArgument<Guid>(0);
            var services = context.HttpContext.RequestServices;

            var userId = services.GetRequiredService<ICurrentUser>().UserId;
            if (userId is not { } uid
                || !await services.GetRequiredService<ITenantMembership>().IsMemberAsync(uid, tenantId, context.HttpContext.RequestAborted))
            {
                return Results.Problem(
                    statusCode: StatusCodes.Status403Forbidden,
                    title: "Not authorized for the requested tenant.");
            }

            services.GetRequiredService<ITenantScopeSetter>().SetTenant(tenantId);
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

        // --- Software-client token management (admin) ---

        // Issue a token for one (project, environment). The plaintext token is returned ONCE.
        group.MapPost(
            "/tenants/{tenantId:guid}/projects/{projectId:guid}/environments/{environment}/tokens",
            async (Guid tenantId, Guid projectId, string environment, IssueTokenRequest body, ISoftwareClientTokenService tokens, CancellationToken ct) =>
            {
                var issued = await tokens.IssueAsync(
                    new IssueSoftwareClientTokenCommand(tenantId, projectId, environment, body.Name, body.ExpiresAt, null), ct);
                return Results.Ok(issued);
            });

        group.MapGet(
            "/tenants/{tenantId:guid}/projects/{projectId:guid}/tokens",
            async (Guid tenantId, Guid projectId, ISoftwareClientTokenService tokens, CancellationToken ct) =>
                Results.Ok(await tokens.ListAsync(tenantId, projectId, ct)));

        // Rotate a token's secret in place (the previous secret stops working). Returns the new token ONCE.
        group.MapPost(
            "/tenants/{tenantId:guid}/projects/{projectId:guid}/tokens/{tokenId:guid}/rotate",
            async (Guid tenantId, Guid projectId, Guid tokenId, RotateTokenRequest? body, ISoftwareClientTokenService tokens, CancellationToken ct) =>
                Results.Ok(await tokens.RotateAsync(tenantId, tokenId, body?.ExpiresAt, null, ct)));

        group.MapDelete(
            "/tenants/{tenantId:guid}/projects/{projectId:guid}/tokens/{tokenId:guid}",
            async (Guid tenantId, Guid projectId, Guid tokenId, ISoftwareClientTokenService tokens, CancellationToken ct) =>
            {
                await tokens.RevokeAsync(tenantId, tokenId, null, ct);
                return Results.NoContent();
            });

        return endpoints;
    }

    public sealed record StoreSecretRequest(string Value);

    public sealed record SecretResponse(string Key, string Value);

    public sealed record IssueTokenRequest(string Name, DateTimeOffset? ExpiresAt);

    public sealed record RotateTokenRequest(DateTimeOffset? ExpiresAt);
}
