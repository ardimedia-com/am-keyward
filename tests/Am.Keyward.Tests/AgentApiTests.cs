using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using Am.Keyward.Api;
using Am.Keyward.Contracts;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Agent;
using Am.Keyward.Core.Domain.Identity;
using Am.Keyward.Infrastructure;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

namespace Am.Keyward.Tests;

/// <summary>
/// The agent read endpoints over real HTTP (in-memory test server with the production middleware order): an
/// agent sees exactly its allowlisted, agent-enabled vaults; everything else answers 404 like a missing
/// resource; no response carries a secret; a Login's url and username are the only decrypted fields.
/// </summary>
[TestClass]
public class AgentApiTests
{
    private static readonly string ConnectionString = TestConfig.ConnectionString;

    [TestMethod, TestCategory("Integration")]
    public async Task Read_endpoints_show_exactly_the_allowlisted_vaults_and_never_a_secret()
    {
        await using var app = await StartAsync();
        if (app is null)
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var services = app.Services;
        var tenantId = Guid.NewGuid();
        var owner = Guid.NewGuid();
        await SeedTenantAsync(services, tenantId, owner);

        Guid allowlisted, other, login, note, otherItem, folder;
        using (var scope = ScopeFor(services, tenantId, owner))
        {
            var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
            allowlisted = await vaults.CreateTenantVaultAsync(new CreateTenantVaultCommand(owner, tenantId, "Integrations"));
            other = await vaults.CreateTenantVaultAsync(new CreateTenantVaultCommand(owner, tenantId, "Other"));
            await vaults.SetAgentAccessAsync(owner, allowlisted, allowed: true);
            await vaults.SetAgentAccessAsync(owner, other, allowed: true);
            folder = await vaults.AddFolderAsync(new AddVaultFolderCommand(owner, allowlisted, "Carriers"));
            login = await vaults.AddItemAsync(new AddVaultItemCommand(owner, allowlisted, folder, ItemType.Login, "CH-Post API",
                LoginContent.ToJson("https://api.post.ch", "bvd-client", "s3cr3t-password", "rotate yearly")));
            note = await vaults.AddItemAsync(new AddVaultItemCommand(owner, allowlisted, null, ItemType.SecureNote, "Post contract note", "confidential-note"));
            otherItem = await vaults.AddItemAsync(new AddVaultItemCommand(owner, other, null, ItemType.Generic, "Post other vault", "other-secret"));
        }

        var client = app.GetTestClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer",
            await IssueAsync(services, tenantId, owner, allowlisted, AgentScopes.VaultList | AgentScopes.VaultRead));

        // Only the allowlisted vault, although the user can also reach «Other» and it is open to agents.
        var list = await client.GetFromJsonAsync<List<AgentVaultResponse>>("/keyward/api/v1/agent/vaults");
        CollectionAssert.AreEqual(new[] { allowlisted }, list!.Select(v => v.Id).ToArray());

        var tree = await client.GetFromJsonAsync<AgentVaultTreeResponse>($"/keyward/api/v1/agent/vaults/{allowlisted}/tree");
        Assert.AreEqual("Integrations", tree!.VaultName);
        Assert.AreEqual(folder, tree.Folders.Single().Id);
        CollectionAssert.AreEquivalent(new[] { login, note }, tree.Items.Select(i => i.Id).ToArray());
        Assert.AreEqual(HttpStatusCode.NotFound, (await client.GetAsync($"/keyward/api/v1/agent/vaults/{other}/tree")).StatusCode);

        // Search: names only, only in reachable vaults.
        var hits = await client.GetFromJsonAsync<List<AgentItemSummaryResponse>>("/keyward/api/v1/agent/search?q=post");
        CollectionAssert.AreEquivalent(new[] { login, note }, hits!.Select(h => h.Id).ToArray());
        Assert.AreEqual(HttpStatusCode.BadRequest, (await client.GetAsync("/keyward/api/v1/agent/search?q=p")).StatusCode);

        // A Login: url and username, never the password or the note — checked on the raw body.
        var response = await client.GetAsync($"/keyward/api/v1/agent/items/{login}");
        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("s3cr3t-password", body);
        Assert.DoesNotContain("rotate yearly", body);
        var item = System.Text.Json.JsonSerializer.Deserialize<AgentItemResponse>(body, new System.Text.Json.JsonSerializerOptions(System.Text.Json.JsonSerializerDefaults.Web))!;
        Assert.AreEqual("https://api.post.ch", item.Url);
        Assert.AreEqual("bvd-client", item.Username);
        Assert.AreEqual("Login", item.Type);
        Assert.StartsWith(KeywardApiDefaults.EntryLinkPath + "/", item.Link);
        Assert.AreEqual($"\"{item.VersionId}\"", response.Headers.ETag?.Tag);
        Assert.IsTrue(response.Headers.CacheControl?.NoStore);

        // Other types: no value at all.
        var noteBody = await (await client.GetAsync($"/keyward/api/v1/agent/items/{note}")).Content.ReadAsStringAsync();
        Assert.DoesNotContain("confidential-note", noteBody);

        // Outside the allowlist, unknown, or without a token.
        Assert.AreEqual(HttpStatusCode.NotFound, (await client.GetAsync($"/keyward/api/v1/agent/items/{otherItem}")).StatusCode);
        Assert.AreEqual(HttpStatusCode.NotFound, (await client.GetAsync($"/keyward/api/v1/agent/items/{Guid.NewGuid()}")).StatusCode);
        var anonymous = app.GetTestClient();
        Assert.AreEqual(HttpStatusCode.Unauthorized, (await anonymous.GetAsync("/keyward/api/v1/agent/vaults")).StatusCode);

        // The metadata read decrypted a Login, so it is audited — as the agent, with its token.
        using (var scope = ScopeFor(services, tenantId, owner))
        {
            var entry = await scope.ServiceProvider.GetRequiredService<KeywardDbContext>().AuditEntries.AsNoTracking()
                .SingleAsync(a => a.TenantId == tenantId && a.ResourceType == "VaultItemMetadata" && a.ResourceId == login);
            Assert.AreEqual(ActorKind.Agent, entry.ActorKind);
            Assert.IsNotNull(entry.ActorTokenId);
        }
    }

    [TestMethod, TestCategory("Integration")]
    public async Task A_token_without_the_read_scope_cannot_open_items()
    {
        await using var app = await StartAsync();
        if (app is null)
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var services = app.Services;
        var tenantId = Guid.NewGuid();
        var owner = Guid.NewGuid();
        await SeedTenantAsync(services, tenantId, owner);

        Guid vault, login;
        using (var scope = ScopeFor(services, tenantId, owner))
        {
            var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
            vault = await vaults.CreateTenantVaultAsync(new CreateTenantVaultCommand(owner, tenantId, "Integrations"));
            await vaults.SetAgentAccessAsync(owner, vault, allowed: true);
            login = await vaults.AddItemAsync(new AddVaultItemCommand(owner, vault, null, ItemType.Login, "DHL",
                LoginContent.ToJson("https://dhl", "user", "pw", "")));
        }

        var client = app.GetTestClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer",
            await IssueAsync(services, tenantId, owner, vault, AgentScopes.VaultList));

        Assert.AreEqual(HttpStatusCode.OK, (await client.GetAsync($"/keyward/api/v1/agent/vaults/{vault}/tree")).StatusCode);
        Assert.AreEqual(HttpStatusCode.NotFound, (await client.GetAsync($"/keyward/api/v1/agent/items/{login}")).StatusCode);
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Write_endpoints_create_and_patch_without_echoing_and_refuse_stale_versions()
    {
        await using var app = await StartAsync();
        if (app is null)
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var services = app.Services;
        var tenantId = Guid.NewGuid();
        var owner = Guid.NewGuid();
        await SeedTenantAsync(services, tenantId, owner);

        Guid vault, other, otherFolder;
        using (var scope = ScopeFor(services, tenantId, owner))
        {
            var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
            vault = await vaults.CreateTenantVaultAsync(new CreateTenantVaultCommand(owner, tenantId, "Integrations"));
            other = await vaults.CreateTenantVaultAsync(new CreateTenantVaultCommand(owner, tenantId, "Other"));
            await vaults.SetAgentAccessAsync(owner, vault, allowed: true);
            await vaults.SetAgentAccessAsync(owner, other, allowed: true);
            otherFolder = await vaults.AddFolderAsync(new AddVaultFolderCommand(owner, other, "Elsewhere"));
        }

        var client = app.GetTestClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer",
            await IssueAsync(services, tenantId, owner, vault, AgentScopes.VaultList | AgentScopes.VaultRead | AgentScopes.VaultWrite));
        var items = $"/keyward/api/v1/agent/vaults/{vault}/items";

        // Create a Login: 201, the secret is not in the response.
        var created = await client.PostAsJsonAsync(items, new AgentCreateItemRequest("Login", "CH-Post API",
            Url: "https://api.post.ch", Username: "bvd-client", Password: "first-password", Note: "from the e-mail of 2026-09-25"));
        Assert.AreEqual(HttpStatusCode.Created, created.StatusCode);
        var createdBody = await created.Content.ReadAsStringAsync();
        Assert.DoesNotContain("first-password", createdBody);
        var written = await created.Content.ReadFromJsonAsync<AgentItemWrittenResponse>();
        Assert.AreEqual($"\"{written!.VersionId}\"", created.Headers.ETag?.Tag);

        // Other types take value; wrong shapes are refused.
        Assert.AreEqual(HttpStatusCode.Created, (await client.PostAsJsonAsync(items, new AgentCreateItemRequest("ApiCredential", "DHL key", Value: "dhl-key"))).StatusCode);
        Assert.AreEqual(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync(items, new AgentCreateItemRequest("Login", "x", Value: "v"))).StatusCode);
        Assert.AreEqual(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync(items, new AgentCreateItemRequest("SecureNote", "x"))).StatusCode);
        Assert.AreEqual(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync(items, new AgentCreateItemRequest("Password", "x", Value: "v"))).StatusCode);
        Assert.AreEqual(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync(items, new AgentCreateItemRequest("Generic", "x", FolderId: otherFolder, Value: "v"))).StatusCode);

        // Outside the allowlist: 404 like a missing vault.
        Assert.AreEqual(HttpStatusCode.NotFound, (await client.PostAsJsonAsync($"/keyward/api/v1/agent/vaults/{other}/items", new AgentCreateItemRequest("Generic", "x", Value: "v"))).StatusCode);

        // Patch: If-Match is required; only the password changes, the other fields stay.
        var itemUrl = $"/keyward/api/v1/agent/items/{written.Id}";
        Assert.AreEqual(HttpStatusCode.PreconditionRequired, (await client.PatchAsJsonAsync(itemUrl, new AgentUpdateItemRequest(Password: "second"))).StatusCode);

        var patch = new HttpRequestMessage(HttpMethod.Patch, itemUrl) { Content = JsonContent.Create(new AgentUpdateItemRequest(Password: "second-password")) };
        patch.Headers.IfMatch.Add(new EntityTagHeaderValue($"\"{written.VersionId}\""));
        var patched = await client.SendAsync(patch);
        Assert.AreEqual(HttpStatusCode.OK, patched.StatusCode);
        Assert.DoesNotContain("second-password", await patched.Content.ReadAsStringAsync());
        var afterPatch = await patched.Content.ReadFromJsonAsync<AgentItemWrittenResponse>();
        Assert.AreNotEqual(written.VersionId, afterPatch!.VersionId);

        using (var scope = ScopeFor(services, tenantId, owner))
        {
            var fields = LoginContent.Parse(await scope.ServiceProvider.GetRequiredService<IVaultService>().ReadItemAsync(owner, written.Id));
            Assert.AreEqual("second-password", fields.Password);
            Assert.AreEqual("https://api.post.ch", fields.Url);
            Assert.AreEqual("bvd-client", fields.Username);
            Assert.AreEqual("from the e-mail of 2026-09-25", fields.Note);
        }

        // Replaying the old version is refused: the change in between is not overwritten.
        var stale = new HttpRequestMessage(HttpMethod.Patch, itemUrl) { Content = JsonContent.Create(new AgentUpdateItemRequest(Password: "third")) };
        stale.Headers.IfMatch.Add(new EntityTagHeaderValue($"\"{written.VersionId}\""));
        Assert.AreEqual(HttpStatusCode.PreconditionFailed, (await client.SendAsync(stale)).StatusCode);

        // A Login field on a non-Login is refused.
        var bad = new HttpRequestMessage(HttpMethod.Patch, itemUrl) { Content = JsonContent.Create(new AgentUpdateItemRequest(Value: "v")) };
        bad.Headers.IfMatch.Add(new EntityTagHeaderValue($"\"{afterPatch.VersionId}\""));
        Assert.AreEqual(HttpStatusCode.BadRequest, (await client.SendAsync(bad)).StatusCode);

        // Both writes are audited as the agent.
        using (var scope = ScopeFor(services, tenantId, owner))
        {
            var entries = await scope.ServiceProvider.GetRequiredService<KeywardDbContext>().AuditEntries.AsNoTracking()
                .Where(a => a.TenantId == tenantId && a.ResourceType == "VaultItem" && a.ResourceId == written.Id)
                .ToListAsync();
            Assert.IsTrue(entries.Any(e => e.Action == AuditAction.Create && e.ActorKind == ActorKind.Agent));
            Assert.IsTrue(entries.Any(e => e.Action == AuditAction.Update && e.ActorKind == ActorKind.Agent));
        }

        // A token without the write scope can neither create nor change.
        var readOnly = app.GetTestClient();
        readOnly.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer",
            await IssueAsync(services, tenantId, owner, vault, AgentScopes.VaultList | AgentScopes.VaultRead));
        Assert.AreEqual(HttpStatusCode.NotFound, (await readOnly.PostAsJsonAsync(items, new AgentCreateItemRequest("Generic", "x", Value: "v"))).StatusCode);
        var readOnlyPatch = new HttpRequestMessage(HttpMethod.Patch, itemUrl) { Content = JsonContent.Create(new AgentUpdateItemRequest(Name: "renamed")) };
        readOnlyPatch.Headers.IfMatch.Add(new EntityTagHeaderValue($"\"{afterPatch.VersionId}\""));
        Assert.AreEqual(HttpStatusCode.NotFound, (await readOnly.SendAsync(readOnlyPatch)).StatusCode);
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Two_concurrent_patches_from_the_same_version_never_both_win()
    {
        await using var app = await StartAsync();
        if (app is null)
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var services = app.Services;
        var tenantId = Guid.NewGuid();
        var owner = Guid.NewGuid();
        await SeedTenantAsync(services, tenantId, owner);

        Guid itemId, version;
        using (var scope = ScopeFor(services, tenantId, owner))
        {
            var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
            var vault = await vaults.CreateTenantVaultAsync(new CreateTenantVaultCommand(owner, tenantId, "Race"));
            itemId = await vaults.AddItemAsync(new AddVaultItemCommand(owner, vault, null, ItemType.Generic, "key", "v0"));
            version = (await vaults.GetItemReferenceAsync(owner, itemId))!.VersionId;
        }

        async Task<bool> PatchAsync(string value)
        {
            using var scope = ScopeFor(services, tenantId, owner);
            try
            {
                await scope.ServiceProvider.GetRequiredService<IVaultService>()
                    .PatchItemAsync(new PatchVaultItemCommand(owner, itemId, version, Value: value));
                return true;
            }
            catch (VaultItemVersionConflictException)
            {
                return false;
            }
        }

        var results = await Task.WhenAll(Enumerable.Range(1, 6).Select(i => PatchAsync($"v{i}")));
        Assert.AreEqual(1, results.Count(r => r), "Exactly one writer may move the item past the version all of them started from.");
    }

    // The production pipeline order: rate limiter before authentication, then authorization, then endpoints.
    internal static async Task<WebApplication?> StartAsync(Action<IServiceCollection>? configure = null)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddKeyward(ConnectionString, RandomNumberGenerator.GetBytes(32), "test-kek:v1");
        builder.Services.AddKeywardAgentApi();

        // Endpoints only: Keyward's background services must not run against the shared test database — the
        // KEK integrity check would seal it with this run's random test key and break every later test.
        builder.Services.RemoveAll<IHostedService>();
        configure?.Invoke(builder.Services);

        var app = builder.Build();
        app.UseRateLimiter();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapKeywardAgentApi();

        using (var probe = app.Services.CreateScope())
        {
            if (!await probe.ServiceProvider.GetRequiredService<KeywardDbContext>().Database.CanConnectAsync())
            {
                await app.DisposeAsync();
                return null;
            }
        }

        await app.StartAsync();
        return app;
    }

    internal static async Task<string> IssueAsync(IServiceProvider services, Guid tenantId, Guid userId, Guid vaultId, AgentScopes scopes)
    {
        using var scope = ScopeFor(services, tenantId, userId);
        var issued = await scope.ServiceProvider.GetRequiredService<IAgentTokenService>()
            .IssueAsync(new IssueAgentTokenCommand(userId, tenantId, $"agent-{Guid.NewGuid():N}", scopes, [vaultId]));
        return issued.Token;
    }

    internal static async Task SeedTenantAsync(IServiceProvider services, Guid tenantId, Guid userId)
    {
        using var scope = services.CreateScope();
        scope.ServiceProvider.GetRequiredService<ITenantScopeSetter>().SetTenant(tenantId);
        var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
        db.Tenants.Add(new Tenant(tenantId, "agent-api-test", isSystemTenant: false, DateTimeOffset.UtcNow));
        db.Users.Add(new AppUser(userId, issuer: null, externalId: $"user-{userId:N}", displayName: "agent owner", isSystemAdmin: false, DateTimeOffset.UtcNow));
        db.TenantMemberships.Add(new TenantMembership(Guid.NewGuid(), tenantId, userId, TenantRole.Member, DateTimeOffset.UtcNow));
        await db.SaveChangesAsync();
    }

    internal static IServiceScope ScopeFor(IServiceProvider services, Guid tenantId, Guid userId)
    {
        var scope = services.CreateScope();
        scope.ServiceProvider.GetRequiredService<ITenantScopeSetter>().SetTenant(tenantId);
        scope.ServiceProvider.GetRequiredService<IUserScopeSetter>().SetUser(userId);
        return scope;
    }
}
