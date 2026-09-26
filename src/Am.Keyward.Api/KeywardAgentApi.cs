using System.Security.Claims;
using Am.Keyward.Contracts;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Agent;
using Am.Keyward.Core.Support;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Am.Keyward.Api;

/// <summary>
/// The agent API: an AI assistant presents an agent token and works with vault items as the token's user,
/// narrowed by the token's scopes and vault allowlist (see <see cref="AgentAuthenticationHandler"/>). Every
/// vault or item endpoint decides access per request through <see cref="IAgentVaultAccess"/>; a vault or item
/// the token may not reach answers exactly like one that does not exist (404), so the API is no existence
/// oracle. No response ever carries a secret value.
/// </summary>
public static class KeywardAgentApi
{
    /// <summary>Rate-limiter policy name (registered by <c>AddKeywardAgentApi</c>), partitioned per token.</summary>
    public const string RateLimiterPolicy = "keyward-agent";

    /// <summary>Default base path of the agent endpoints.</summary>
    public const string DefaultPrefix = KeywardApiDefaults.BasePath + "/agent";

    private const int MaxSearchHits = 100;

    // Upper bound for any single text field an agent sends (names are capped at 256 by the model).
    private const int MaxFieldLength = 32_768;

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

        // The vaults this token may list: the user's team vaults, narrowed to the allowlist and the agent flag.
        group.MapGet("/vaults", async (ClaimsPrincipal principal, ICurrentUser user, ICurrentTenant tenant,
            IVaultService vaults, IAgentVaultAccess access, CancellationToken ct) =>
        {
            var reachable = await ReachableVaultsAsync(principal, user, tenant, vaults, access, ct);
            return Results.Ok(reachable.Select(v => new AgentVaultResponse(v.Id, v.Name)).ToList());
        });

        group.MapGet("/vaults/{vaultId:guid}/tree", async (Guid vaultId, ClaimsPrincipal principal, ICurrentUser user,
            ICurrentTenant tenant, IVaultService vaults, IAgentVaultAccess access, CancellationToken ct) =>
        {
            if (!await access.IsVaultAllowedAsync(TokenId(principal), vaultId, AgentScopes.VaultList, Permission.Read, ct))
            {
                return NotFound();
            }

            var userId = UserId(user);
            var vault = (await vaults.ListSharedVaultsAsync(userId, TenantId(tenant), ct)).First(v => v.Id == vaultId);
            var folders = await vaults.ListFoldersAsync(userId, vaultId, ct);
            var items = await vaults.ListItemsAsync(userId, vaultId, ct);

            return Results.Ok(new AgentVaultTreeResponse(
                vault.Id,
                vault.Name,
                folders.Select(f => new AgentFolderResponse(f.Id, f.Name, f.ParentFolderId)).ToList(),
                items.Select(i => new AgentItemSummaryResponse(i.Id, vaultId, i.FolderId, i.Type.ToString(), i.Name)).ToList()));
        });

        // Name search across the reachable vaults. Names are cleartext; nothing is decrypted.
        group.MapGet("/search", async (string? q, ClaimsPrincipal principal, ICurrentUser user, ICurrentTenant tenant,
            IVaultService vaults, IAgentVaultAccess access, CancellationToken ct) =>
        {
            if (q is null || q.Trim().Length < 2)
            {
                return Results.Problem(statusCode: StatusCodes.Status400BadRequest, title: "The search needs at least 2 characters (q).");
            }

            var reachable = await ReachableVaultsAsync(principal, user, tenant, vaults, access, ct);
            var hits = await vaults.SearchItemNamesAsync(UserId(user), reachable.Select(v => v.Id).ToList(), q, MaxSearchHits, ct);
            return Results.Ok(hits.Select(h => new AgentItemSummaryResponse(h.ItemId, h.VaultId, h.FolderId, h.Type.ToString(), h.Name)).ToList());
        });

        // One item without its secret. A Login's url and username come along; password and note never do.
        group.MapGet("/items/{itemId:guid}", async (Guid itemId, HttpContext http, ClaimsPrincipal principal, ICurrentUser user,
            IVaultService vaults, IAgentVaultAccess access, CancellationToken ct) =>
        {
            if (!await access.IsItemAllowedAsync(TokenId(principal), itemId, AgentScopes.VaultRead, Permission.Read, ct))
            {
                return NotFound();
            }

            var item = await vaults.GetItemMetadataAsync(UserId(user), itemId, ct);
            if (item is null)
            {
                return NotFound();
            }

            http.Response.Headers.CacheControl = "no-store";
            http.Response.Headers.ETag = $"\"{item.VersionId}\"";
            return Results.Ok(new AgentItemResponse(
                item.Id, item.VaultId, item.FolderId, item.Type.ToString(), item.Name,
                $"{KeywardApiDefaults.EntryLinkPath}/{Base62Guid.Encode(item.PublicId)}",
                item.VersionId, item.Url, item.Username));
        });

        // Create an item. Needs the write scope and Write on the vault; the value is never echoed.
        group.MapPost("/vaults/{vaultId:guid}/items", async (Guid vaultId, AgentCreateItemRequest body, HttpContext http,
            ClaimsPrincipal principal, ICurrentUser user, IVaultService vaults, IAgentVaultAccess access, CancellationToken ct) =>
        {
            if (!await access.IsVaultAllowedAsync(TokenId(principal), vaultId, AgentScopes.VaultWrite, Permission.Write, ct))
            {
                return NotFound();
            }

            if (!TryBuildContent(body, out var type, out var content, out var error))
            {
                return BadRequest(error);
            }

            try
            {
                var userId = UserId(user);
                var itemId = await vaults.AddItemAsync(new AddVaultItemCommand(userId, vaultId, body.FolderId, type, body.Name, content), ct);
                var reference = await vaults.GetItemReferenceAsync(userId, itemId, ct)
                    ?? throw new InvalidOperationException($"Item {itemId} vanished right after it was created.");
                return Written(http, reference, StatusCodes.Status201Created);
            }
            catch (ArgumentException ex)
            {
                return BadRequest(ex.Message);
            }
            catch (InvalidOperationException ex) when (ex is not VaultItemVersionConflictException)
            {
                // e.g. a folder that is not in this vault.
                return BadRequest(ex.Message);
            }
        });

        // Change an item. Requires If-Match with the version the agent last read, so a change made in between is
        // never overwritten silently (412), even by a concurrent writer.
        group.MapPatch("/items/{itemId:guid}", async (Guid itemId, AgentUpdateItemRequest body, HttpContext http,
            ClaimsPrincipal principal, ICurrentUser user, IVaultService vaults, IAgentVaultAccess access, CancellationToken ct) =>
        {
            if (!await access.IsItemAllowedAsync(TokenId(principal), itemId, AgentScopes.VaultWrite, Permission.Write, ct))
            {
                return NotFound();
            }

            if (!TryReadIfMatch(http, out var expectedVersion))
            {
                return Results.Problem(statusCode: StatusCodes.Status428PreconditionRequired,
                    title: "Send If-Match with the item's version (the ETag of GET /items/{id}).");
            }

            if (TooLong(body.Name, body.Url, body.Username, body.Password, body.Note, body.Value))
            {
                return BadRequest($"A field exceeds {MaxFieldLength} characters.");
            }

            try
            {
                var reference = await vaults.PatchItemAsync(new PatchVaultItemCommand(
                    UserId(user), itemId, expectedVersion, body.Name, body.Url, body.Username, body.Password, body.Note, body.Value), ct);
                return Written(http, reference, StatusCodes.Status200OK);
            }
            catch (VaultItemVersionConflictException ex)
            {
                return Results.Problem(statusCode: StatusCodes.Status412PreconditionFailed, title: ex.Message);
            }
            catch (ArgumentException ex)
            {
                return BadRequest(ex.Message);
            }
        });

        return endpoints;
    }

    // One request shape for every type: a Login is built from its four fields, anything else takes value.
    private static bool TryBuildContent(AgentCreateItemRequest body, out ItemType type, out string content, out string error)
    {
        content = "";
        error = "";
        if (!Enum.TryParse(body.Type, ignoreCase: true, out type) || !Enum.IsDefined(type))
        {
            error = $"Unknown item type '{body.Type}'. Use one of: {string.Join(", ", Enum.GetNames<ItemType>())}.";
            return false;
        }

        if (string.IsNullOrWhiteSpace(body.Name))
        {
            error = "An item needs a name.";
            return false;
        }

        if (TooLong(body.Name, body.Url, body.Username, body.Password, body.Note, body.Value))
        {
            error = $"A field exceeds {MaxFieldLength} characters.";
            return false;
        }

        var loginFieldGiven = body.Url is not null || body.Username is not null || body.Password is not null || body.Note is not null;
        if (type == ItemType.Login)
        {
            if (body.Value is not null)
            {
                error = "A Login takes url, username, password and note, not value.";
                return false;
            }

            content = LoginContent.ToJson(body.Url ?? "", body.Username ?? "", body.Password ?? "", body.Note ?? "");
            return true;
        }

        if (loginFieldGiven || body.Value is null)
        {
            error = $"A {type} takes value (and no url, username, password or note).";
            return false;
        }

        content = body.Value;
        return true;
    }

    private static bool TooLong(params string?[] fields) => fields.Any(f => f is { Length: > MaxFieldLength });

    // Accepts "guid", W/"guid" or a bare guid.
    private static bool TryReadIfMatch(HttpContext http, out Guid version)
    {
        var raw = http.Request.Headers.IfMatch.ToString().Trim();
        if (raw.StartsWith("W/", StringComparison.Ordinal))
        {
            raw = raw[2..];
        }

        return Guid.TryParse(raw.Trim('"'), out version);
    }

    private static IResult Written(HttpContext http, VaultItemReference reference, int statusCode)
    {
        http.Response.Headers.ETag = $"\"{reference.VersionId}\"";
        var response = new AgentItemWrittenResponse(
            reference.Id, $"{KeywardApiDefaults.EntryLinkPath}/{Base62Guid.Encode(reference.PublicId)}", reference.VersionId);
        return statusCode == StatusCodes.Status201Created
            ? Results.Created((string?)null, response)
            : Results.Ok(response);
    }

    private static IResult BadRequest(string title) =>
        Results.Problem(statusCode: StatusCodes.Status400BadRequest, title: title);

    private static async Task<IReadOnlyList<VaultSummary>> ReachableVaultsAsync(
        ClaimsPrincipal principal, ICurrentUser user, ICurrentTenant tenant, IVaultService vaults, IAgentVaultAccess access, CancellationToken ct)
    {
        var tokenId = TokenId(principal);
        var candidates = await vaults.ListSharedVaultsAsync(UserId(user), TenantId(tenant), ct);

        var reachable = new List<VaultSummary>();
        foreach (var vault in candidates.Where(v => v.AgentAccessAllowed))
        {
            if (await access.IsVaultAllowedAsync(tokenId, vault.Id, AgentScopes.VaultList, Permission.Read, ct))
            {
                reachable.Add(vault);
            }
        }

        return reachable;
    }

    private static IResult NotFound() =>
        Results.Problem(statusCode: StatusCodes.Status404NotFound, title: "Not found.");

    // Set by AgentAuthenticationHandler for every authenticated agent request.
    private static Guid TokenId(ClaimsPrincipal principal) =>
        Guid.Parse(principal.FindFirstValue(AgentAuthenticationHandler.TokenIdClaim)!);

    private static Guid UserId(ICurrentUser user) =>
        user.UserId ?? throw new InvalidOperationException("The agent handler did not establish the user scope.");

    private static Guid TenantId(ICurrentTenant tenant) =>
        tenant.TenantId ?? throw new InvalidOperationException("The agent handler did not establish the tenant scope.");
}
