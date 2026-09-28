using System.Security.Claims;
using Am.Keyward.Contracts;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain.Agent;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Am.Keyward.Api;

/// <summary>
/// The application part of the agent API (<see cref="AgentScopes.ManageApplications"/>): an assistant sets up an
/// application for the software-client API — the application, its environments and its keys — and hands a person
/// the link to paste the values. It may set a value itself, write-only. App tokens stay with people: there is no
/// endpoint for them, only the link to the page where a person issues one.
/// <para>
/// Every call goes through <see cref="IAgentApplicationService"/>, which decides the token's reach per request and
/// delegates to the services the UI uses. Without the permission the collection endpoints answer 403; anything out
/// of reach answers 404, exactly like something missing. No response carries a value.
/// </para>
/// </summary>
internal static class KeywardAgentApplicationsApi
{
    // The same upper bound the item endpoints apply to any single text field.
    private const int MaxValueLength = 32_768;

    public static void MapAgentApplications(this RouteGroupBuilder group)
    {
        // What the token may do — for «amkeyward-mcp check». Tells nothing beyond the token's own settings.
        group.MapGet("/token", async (ClaimsPrincipal principal, ICurrentUser user, ICurrentTenant tenant,
            IAgentTokenService tokens, CancellationToken ct) =>
        {
            var tokenId = KeywardAgentApi.TokenId(principal);
            var own = await tokens.ListAsync(KeywardAgentApi.UserId(user), KeywardAgentApi.TenantId(tenant), ct);
            var token = own.Single(t => t.Id == tokenId);
            var permissions = Enum.GetValues<AgentScopes>()
                .Where(s => s != AgentScopes.None && token.Scopes.HasFlag(s))
                .Select(s => s.ToString())
                .ToList();
            return Results.Ok(new AgentTokenInfoResponse(
                token.Id, token.Name, permissions, token.VaultIds.Count, token.ApplicationIds.Count,
                token.MayCreateApplications, token.AllowedNetworks, token.ExpiresAt));
        });

        group.MapGet("/applications", (ClaimsPrincipal principal, IAgentApplicationService applications, CancellationToken ct) =>
            Guarded(collection: true, async () =>
            {
                var list = await applications.ListAsync(KeywardAgentApi.TokenId(principal), ct);
                return Results.Ok(list.Select(ToResponse).ToList());
            }));

        group.MapPost("/applications", (AgentCreateApplicationRequest body, ClaimsPrincipal principal,
            IAgentApplicationService applications, CancellationToken ct) =>
            Guarded(collection: true, async () =>
            {
                var tokenId = KeywardAgentApi.TokenId(principal);
                var id = await applications.CreateAsync(tokenId, body.Name ?? "", body.Environments ?? [], ct);
                var view = await applications.GetAsync(tokenId, id, ct);
                return Results.Created(ApplicationLink(id), ToResponse(view));
            }));

        group.MapGet("/applications/{applicationId:guid}", (Guid applicationId, ClaimsPrincipal principal,
            IAgentApplicationService applications, CancellationToken ct) =>
            Guarded(collection: false, async () =>
                Results.Ok(ToResponse(await applications.GetAsync(KeywardAgentApi.TokenId(principal), applicationId, ct)))));

        group.MapPatch("/applications/{applicationId:guid}", (Guid applicationId, AgentRenameApplicationRequest body,
            ClaimsPrincipal principal, IAgentApplicationService applications, CancellationToken ct) =>
            Guarded(collection: false, async () =>
            {
                var tokenId = KeywardAgentApi.TokenId(principal);
                await applications.RenameAsync(tokenId, applicationId, body.Name ?? "", ct);
                return Results.Ok(ToResponse(await applications.GetAsync(tokenId, applicationId, ct)));
            }));

        group.MapDelete("/applications/{applicationId:guid}", (Guid applicationId, ClaimsPrincipal principal,
            IAgentApplicationService applications, CancellationToken ct) =>
            Guarded(collection: false, async () =>
            {
                await applications.DeleteAsync(KeywardAgentApi.TokenId(principal), applicationId, ct);
                return Results.NoContent();
            }));

        group.MapPost("/applications/{applicationId:guid}/environments", (Guid applicationId, AgentAddEnvironmentRequest body,
            ClaimsPrincipal principal, IAgentApplicationService applications, CancellationToken ct) =>
            Guarded(collection: false, async () =>
            {
                var tokenId = KeywardAgentApi.TokenId(principal);
                await applications.AddEnvironmentAsync(tokenId, applicationId, body.Name ?? "", ct);
                return Results.Created(ApplicationLink(applicationId), ToResponse(await applications.GetAsync(tokenId, applicationId, ct)));
            }));

        group.MapPost("/applications/{applicationId:guid}/secrets", (Guid applicationId, AgentCreateSecretRequest body,
            HttpContext http, ClaimsPrincipal principal, IAgentApplicationService applications, CancellationToken ct) =>
            Guarded(collection: false, async () =>
            {
                if (body.Value is { Length: > MaxValueLength })
                {
                    return BadRequest($"A value may have at most {MaxValueLength} characters.");
                }

                var stored = await applications.CreateSecretAsync(
                    KeywardAgentApi.TokenId(principal), applicationId, body.Key ?? "", body.Environment, body.Value, ct);
                return Written(http, applicationId, body.Key ?? "", body.Environment, stored, StatusCodes.Status201Created);
            }));

        // Replaces (or first sets) one environment's value. Optimistic concurrency like PATCH /items: If-Match with the
        // version from GET /applications, or If-None-Match: * while the environment holds no value yet.
        group.MapPut("/applications/{applicationId:guid}/secrets/{key}", (Guid applicationId, string key, AgentSetSecretValueRequest body,
            HttpContext http, ClaimsPrincipal principal, IAgentApplicationService applications, CancellationToken ct) =>
            Guarded(collection: false, async () =>
            {
                if (!TryReadPrecondition(http, out var precondition))
                {
                    return Results.Problem(statusCode: StatusCodes.Status428PreconditionRequired,
                        title: "Send If-Match with the value's version (from GET /applications), or If-None-Match: * when it holds no value yet.");
                }

                if (body.Value is null or { Length: 0 } || body.Value.Length > MaxValueLength)
                {
                    return BadRequest($"A value needs 1 to {MaxValueLength} characters.");
                }

                var stored = await applications.SetSecretValueAsync(
                    KeywardAgentApi.TokenId(principal), applicationId, key, body.Environment ?? "", body.Value, precondition, ct);
                return Written(http, applicationId, key, body.Environment, stored, StatusCodes.Status200OK);
            }));

        group.MapPatch("/applications/{applicationId:guid}/secrets/{key}", (Guid applicationId, string key, AgentRenameSecretRequest body,
            ClaimsPrincipal principal, IAgentApplicationService applications, CancellationToken ct) =>
            Guarded(collection: false, async () =>
            {
                await applications.RenameSecretAsync(KeywardAgentApi.TokenId(principal), applicationId, key, body.Key ?? "", ct);
                return Results.NoContent();
            }));

        group.MapDelete("/applications/{applicationId:guid}/secrets/{key}", (Guid applicationId, string key,
            ClaimsPrincipal principal, IAgentApplicationService applications, CancellationToken ct) =>
            Guarded(collection: false, async () =>
            {
                await applications.DeleteSecretAsync(KeywardAgentApi.TokenId(principal), applicationId, key, ct);
                return Results.NoContent();
            }));
    }

    // One mapping from the service's outcomes to RFC 9457 problems, so every endpoint answers alike.
    private static async Task<IResult> Guarded(bool collection, Func<Task<IResult>> action)
    {
        try
        {
            return await action();
        }
        catch (AgentApplicationsNotPermittedException ex)
        {
            // On a collection the permission is all there is to know; on one application it must not tell existence.
            return collection
                ? Results.Problem(statusCode: StatusCodes.Status403Forbidden, title: ex.Message)
                : KeywardAgentApi.NotFound();
        }
        catch (AgentApplicationNotFoundException)
        {
            return KeywardAgentApi.NotFound();
        }
        catch (AgentApplicationChangeRefusedException ex)
        {
            return Results.Problem(statusCode: StatusCodes.Status403Forbidden, title: ex.Message);
        }
        catch (SecretValueVersionConflictException ex)
        {
            return Results.Problem(statusCode: StatusCodes.Status412PreconditionFailed, title: ex.Message);
        }
        catch (AgentApplicationConflictException ex)
        {
            return Results.Problem(statusCode: StatusCodes.Status409Conflict, title: ex.Message);
        }
        catch (ArgumentException ex)
        {
            return BadRequest(ex.Message);
        }
        catch (UnauthorizedAccessException)
        {
            // A guard inside the shared services (e.g. the user lost a role mid-request): out of reach.
            return KeywardAgentApi.NotFound();
        }
    }

    private static bool TryReadPrecondition(HttpContext http, out SecretValuePrecondition precondition)
    {
        precondition = new SecretValuePrecondition(null);
        if (http.Request.Headers.IfNoneMatch.ToString().Trim() == "*")
        {
            return true;
        }

        if (KeywardAgentApi.TryReadIfMatch(http, out var version))
        {
            precondition = new SecretValuePrecondition(version);
            return true;
        }

        return false;
    }

    private static IResult Written(HttpContext http, Guid applicationId, string key, string? environment, StoredSecretValue? stored, int statusCode)
    {
        if (stored is not null)
        {
            http.Response.Headers.ETag = $"\"{stored.VersionId}\"";
        }

        var response = new AgentSecretWrittenResponse(
            applicationId, key.Trim(), stored is null ? null : environment?.Trim(), stored is not null, stored?.VersionId, DataLink(applicationId));
        return statusCode == StatusCodes.Status201Created
            ? Results.Created(DataLink(applicationId), response)
            : Results.Ok(response);
    }

    private static AgentApplicationResponse ToResponse(AgentApplicationView view) => new(
        view.Id,
        view.Name,
        view.CreatedByThisToken,
        view.Environments,
        view.Keys.Select(k => new AgentSecretKeyResponse(
            k.Key, k.CreatedByThisToken, k.Values.Select(v => new AgentSecretValueStateResponse(v.Environment, v.ValueSet, v.VersionId)).ToList())).ToList(),
        DataLink(view.Id),
        $"{ApplicationLink(view.Id)}&tab=tokens");

    private static string ApplicationLink(Guid applicationId) => $"{KeywardApiDefaults.ApplicationsPath}?app={applicationId}";

    private static string DataLink(Guid applicationId) => $"{ApplicationLink(applicationId)}&tab=data";

    private static IResult BadRequest(string title) =>
        Results.Problem(statusCode: StatusCodes.Status400BadRequest, title: title);
}
