using Am.Keyward.Contracts;
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
    /// <para>
    /// Every route is for software operators only (system admin, tenant admin or software manager) — reading a value
    /// as much as writing one; a plain tenant member gets 403. Errors answer as RFC 9457 problems: 400 for an invalid
    /// request, 403 without the role, 404 for an unknown application, environment or token, 409 for a conflict.
    /// </para>
    /// <para>
    /// The API is usually cookie-authenticated, so a state-changing call (PUT, POST, DELETE) must carry
    /// <c>Content-Type: application/json</c> or the <see cref="KeywardApiDefaults.ManagementRequestHeader"/> header —
    /// neither can come from a cross-site HTML form — otherwise it is refused with 415 before anything happens.
    /// </para>
    /// </summary>
    public static IEndpointRouteBuilder MapKeywardApi(
        this IEndpointRouteBuilder endpoints, string prefix = KeywardApiDefaults.BasePath, string? authorizationPolicy = null)
    {
        // Antiforgery tokens do not fit an API client; the cross-site request guard below takes their place.
        var group = endpoints.MapGroup(prefix).WithTags("Keyward").DisableAntiforgery();

        if (authorizationPolicy is not null)
        {
            group.RequireAuthorization(authorizationPolicy);
        }

        // Cross-site request forgery: a browser sends the auth cookie with a forged form post from any site, but such a
        // post can carry neither a JSON content type nor a custom header (both need a CORS preflight).
        group.AddEndpointFilter(async (context, next) =>
        {
            var request = context.HttpContext.Request;
            if (IsStateChanging(request.Method)
                && !request.HasJsonContentType()
                && !request.Headers.ContainsKey(KeywardApiDefaults.ManagementRequestHeader))
            {
                return Results.Problem(
                    statusCode: StatusCodes.Status415UnsupportedMediaType,
                    title: $"A state-changing call needs Content-Type: application/json or the {KeywardApiDefaults.ManagementRequestHeader} header.");
            }

            return await next(context);
        });

        // Gate the caller-supplied route {tenantId} against the signed-in user's tenant membership, THEN
        // establish the server-authoritative tenant scope from it (so the query filter and row-level security
        // apply). Without the membership check any authenticated user could target any tenant's secrets/tokens
        // by putting that tenant's id in the route. The user is resolved by the host from the auth cookie
        // (see ICurrentUser); system admins are members of every tenant. The services then require the software
        // operator role on every route.
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

        // One mapping from the services' outcomes to problems, so no route answers 500 for a caller's mistake.
        group.AddEndpointFilter(async (context, next) =>
        {
            try
            {
                return await next(context);
            }
            catch (UnauthorizedAccessException)
            {
                return Results.Problem(statusCode: StatusCodes.Status403Forbidden,
                    title: "Managing application data requires the tenant-admin or software-manager role.");
            }
            catch (SoftwareResourceNotFoundException ex)
            {
                return Results.Problem(statusCode: StatusCodes.Status404NotFound, title: ex.Message);
            }
            catch (ArgumentException ex)
            {
                return Results.Problem(statusCode: StatusCodes.Status400BadRequest, title: ex.Message);
            }
            catch (InvalidOperationException ex)
            {
                // A conflict with the current state: a name or key that exists, a concurrent writer, a revoked token.
                return Results.Problem(statusCode: StatusCodes.Status409Conflict, title: ex.Message);
            }
        });

        group.MapPut(
            "/tenants/{tenantId:guid}/projects/{projectId:guid}/environments/{environment}/secrets/{**key}",
            async (Guid tenantId, Guid projectId, string environment, string key, StoreSecretRequest? body, ISoftwareSecretService service, ICurrentUser user, CancellationToken ct) =>
            {
                if (body?.Value is not { } value)
                {
                    return Results.Problem(statusCode: StatusCodes.Status400BadRequest, title: "The request needs a value.");
                }

                await service.StoreAsync(new StoreSoftwareSecretCommand(tenantId, projectId, environment, key, value, user.UserId), ct);
                return Results.NoContent();
            });

        group.MapGet(
            "/tenants/{tenantId:guid}/projects/{projectId:guid}/environments/{environment}/secrets/{**key}",
            async (Guid tenantId, Guid projectId, string environment, string key, HttpContext http, ISoftwareSecretService service, ICurrentUser user, CancellationToken ct) =>
            {
                var value = await service.ReadAsync(new ReadSoftwareSecretQuery(tenantId, projectId, environment, key, user.UserId), ct);
                if (value is null)
                {
                    return Results.Problem(statusCode: StatusCodes.Status404NotFound, title: "No value for this key in this environment.");
                }

                http.Response.Headers.CacheControl = "no-store";
                return Results.Ok(new SecretResponse(key, value));
            });

        // --- Software-client token management (admin) ---

        // Issue a token for one (project, environment). The plaintext token is returned ONCE.
        group.MapPost(
            "/tenants/{tenantId:guid}/projects/{projectId:guid}/environments/{environment}/tokens",
            async (Guid tenantId, Guid projectId, string environment, IssueTokenRequest? body, HttpContext http, ISoftwareClientTokenService tokens, ICurrentUser user, CancellationToken ct) =>
            {
                var issued = await tokens.IssueAsync(
                    new IssueSoftwareClientTokenCommand(tenantId, projectId, environment, body?.Name ?? "", body?.ExpiresAt, user.UserId), ct);
                http.Response.Headers.CacheControl = "no-store";
                return Results.Ok(issued);
            });

        group.MapGet(
            "/tenants/{tenantId:guid}/projects/{projectId:guid}/tokens",
            async (Guid tenantId, Guid projectId, ISoftwareClientTokenService tokens, CancellationToken ct) =>
                Results.Ok(await tokens.ListAsync(tenantId, projectId, ct)));

        // Rotate a token's secret in place (the previous secret stops working). Returns the new token ONCE.
        group.MapPost(
            "/tenants/{tenantId:guid}/projects/{projectId:guid}/tokens/{tokenId:guid}/rotate",
            async (Guid tenantId, Guid projectId, Guid tokenId, RotateTokenRequest? body, HttpContext http, ISoftwareClientTokenService tokens, ICurrentUser user, CancellationToken ct) =>
            {
                if (!await BelongsToProjectAsync(tokens, tenantId, projectId, tokenId, ct))
                {
                    return TokenNotFound();
                }

                var rotated = await tokens.RotateAsync(tenantId, tokenId, TokenExpiryChange.FromNullableKeep(body?.ExpiresAt), user.UserId, ct);
                http.Response.Headers.CacheControl = "no-store";
                return Results.Ok(rotated);
            });

        group.MapDelete(
            "/tenants/{tenantId:guid}/projects/{projectId:guid}/tokens/{tokenId:guid}",
            async (Guid tenantId, Guid projectId, Guid tokenId, ISoftwareClientTokenService tokens, ICurrentUser user, CancellationToken ct) =>
            {
                if (!await BelongsToProjectAsync(tokens, tenantId, projectId, tokenId, ct))
                {
                    return TokenNotFound();
                }

                await tokens.RevokeAsync(tenantId, tokenId, user.UserId, ct);
                return Results.NoContent();
            });

        return endpoints;
    }

    public sealed record StoreSecretRequest(string Value);

    public sealed record IssueTokenRequest(string Name, DateTimeOffset? ExpiresAt);

    public sealed record RotateTokenRequest(DateTimeOffset? ExpiresAt);

    private static bool IsStateChanging(string method) =>
        !(HttpMethods.IsGet(method) || HttpMethods.IsHead(method) || HttpMethods.IsOptions(method) || HttpMethods.IsTrace(method));

    // The route names the application: a token of another application (same tenant) is «not found» there, never
    // rotated or revoked through it.
    private static async Task<bool> BelongsToProjectAsync(
        ISoftwareClientTokenService tokens, Guid tenantId, Guid projectId, Guid tokenId, CancellationToken ct) =>
        (await tokens.ListAsync(tenantId, projectId, ct)).Any(t => t.Id == tokenId);

    private static IResult TokenNotFound() =>
        Results.Problem(statusCode: StatusCodes.Status404NotFound, title: "No such token in this application.");
}
