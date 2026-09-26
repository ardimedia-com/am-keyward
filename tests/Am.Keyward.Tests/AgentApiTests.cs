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

    // The production pipeline order: rate limiter before authentication, then authorization, then endpoints.
    private static async Task<WebApplication?> StartAsync()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddKeyward(ConnectionString, RandomNumberGenerator.GetBytes(32), "test-kek:v1");
        builder.Services.AddKeywardAgentApi();

        // Endpoints only: Keyward's background services must not run against the shared test database — the
        // KEK integrity check would seal it with this run's random test key and break every later test.
        builder.Services.RemoveAll<IHostedService>();

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

    private static async Task<string> IssueAsync(IServiceProvider services, Guid tenantId, Guid userId, Guid vaultId, AgentScopes scopes)
    {
        using var scope = ScopeFor(services, tenantId, userId);
        var issued = await scope.ServiceProvider.GetRequiredService<IAgentTokenService>()
            .IssueAsync(new IssueAgentTokenCommand(userId, tenantId, $"agent-{Guid.NewGuid():N}", scopes, [vaultId]));
        return issued.Token;
    }

    private static async Task SeedTenantAsync(IServiceProvider services, Guid tenantId, Guid userId)
    {
        using var scope = services.CreateScope();
        scope.ServiceProvider.GetRequiredService<ITenantScopeSetter>().SetTenant(tenantId);
        var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
        db.Tenants.Add(new Tenant(tenantId, "agent-api-test", isSystemTenant: false, DateTimeOffset.UtcNow));
        db.Users.Add(new AppUser(userId, issuer: null, externalId: $"user-{userId:N}", displayName: "agent owner", isSystemAdmin: false, DateTimeOffset.UtcNow));
        db.TenantMemberships.Add(new TenantMembership(Guid.NewGuid(), tenantId, userId, TenantRole.Member, DateTimeOffset.UtcNow));
        await db.SaveChangesAsync();
    }

    private static IServiceScope ScopeFor(IServiceProvider services, Guid tenantId, Guid userId)
    {
        var scope = services.CreateScope();
        scope.ServiceProvider.GetRequiredService<ITenantScopeSetter>().SetTenant(tenantId);
        scope.ServiceProvider.GetRequiredService<IUserScopeSetter>().SetUser(userId);
        return scope;
    }
}
