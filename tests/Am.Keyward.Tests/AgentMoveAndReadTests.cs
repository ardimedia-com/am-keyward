using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Am.Keyward.Contracts;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Agent;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using static Am.Keyward.Tests.AgentApiTests;

namespace Am.Keyward.Tests;

/// <summary>
/// Decision T5 (2026-10-01): an agent may move entries but never delete them, and may read all non-secret metadata —
/// for applications the rotation date and note per value, the app tokens (never their values) and the access
/// statistics.
/// </summary>
[TestClass]
public class AgentMoveAndReadTests
{
    private const string Base = "/keyward/api/v1/agent";

    [TestMethod, TestCategory("Integration")]
    public async Task An_agent_moves_entries_between_folders_and_reachable_vaults_but_cannot_delete()
    {
        await using var app = await StartAsync();
        if (app is null)
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var tenantId = Guid.NewGuid();
        var owner = Guid.NewGuid();
        await SeedTenantAsync(app.Services, tenantId, owner);

        Guid source, target, closed, folder, item;
        string token, readOnlyToken;
        using (var scope = ScopeFor(app.Services, tenantId, owner))
        {
            var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
            source = await vaults.CreateTenantVaultAsync(new CreateTenantVaultCommand(owner, tenantId, "KI-Tresor"));
            target = await vaults.CreateTenantVaultAsync(new CreateTenantVaultCommand(owner, tenantId, "Integrations"));
            closed = await vaults.CreateTenantVaultAsync(new CreateTenantVaultCommand(owner, tenantId, "Closed"));
            await vaults.SetAgentAccessAsync(owner, source, allowed: true);
            await vaults.SetAgentAccessAsync(owner, target, allowed: true);
            folder = await vaults.AddFolderAsync(new AddVaultFolderCommand(owner, source, "Carriers"));
            item = await vaults.AddItemAsync(new AddVaultItemCommand(owner, source, null, ItemType.Generic, "DHL key", "dhl-secret"));
            var tokens = scope.ServiceProvider.GetRequiredService<IAgentTokenService>();
            token = (await tokens.IssueAsync(new IssueAgentTokenCommand(
                owner, tenantId, "mover", AgentScopes.VaultList | AgentScopes.VaultWrite, [source, target]))).Token;
            readOnlyToken = (await tokens.IssueAsync(new IssueAgentTokenCommand(
                owner, tenantId, "reader", AgentScopes.VaultList, [source, target]))).Token;
        }

        var client = Client(app, token);

        // Into a folder of the same vault: same id, same link.
        var intoFolder = await client.PostAsJsonAsync($"{Base}/items/{item}/move", new AgentMoveItemRequest(source, folder));
        Assert.AreEqual(HttpStatusCode.OK, intoFolder.StatusCode);
        var moved = (await intoFolder.Content.ReadFromJsonAsync<AgentItemWrittenResponse>())!;
        Assert.AreEqual(item, moved.Id);
        var tree = await client.GetFromJsonAsync<AgentVaultTreeResponse>($"{Base}/vaults/{source}/tree");
        Assert.AreEqual(folder, tree!.Items.Single(i => i.Id == item).FolderId);

        // A folder that is not in the target vault is refused.
        Assert.AreEqual(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync($"{Base}/items/{item}/move", new AgentMoveItemRequest(target, folder))).StatusCode);

        // Across vaults: a new id, the same link.
        var across = await client.PostAsJsonAsync($"{Base}/items/{item}/move", new AgentMoveItemRequest(target));
        Assert.AreEqual(HttpStatusCode.OK, across.StatusCode);
        var acrossBody = (await across.Content.ReadFromJsonAsync<AgentItemWrittenResponse>())!;
        Assert.AreEqual(moved.Link, acrossBody.Link);
        Assert.IsTrue((await client.GetFromJsonAsync<AgentVaultTreeResponse>($"{Base}/vaults/{target}/tree"))!.Items.Any(i => i.Id == acrossBody.Id));

        // Out of reach: a vault not opened to agents, a token without «Create and update entries».
        Assert.AreEqual(HttpStatusCode.NotFound, (await client.PostAsJsonAsync($"{Base}/items/{acrossBody.Id}/move", new AgentMoveItemRequest(closed))).StatusCode);
        Assert.AreEqual(HttpStatusCode.NotFound,
            (await Client(app, readOnlyToken).PostAsJsonAsync($"{Base}/items/{acrossBody.Id}/move", new AgentMoveItemRequest(source))).StatusCode);

        // No delete, ever.
        var delete = await client.DeleteAsync($"{Base}/items/{acrossBody.Id}");
        Assert.IsTrue(delete.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.MethodNotAllowed, delete.StatusCode.ToString());
    }

    [TestMethod, TestCategory("Integration")]
    public async Task An_agent_reads_rotation_info_and_audits_its_reads()
    {
        await using var app = await StartAsync();
        if (app is null)
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var tenantId = Guid.NewGuid();
        var owner = Guid.NewGuid();
        await SeedTenantAsync(app.Services, tenantId, owner);

        Guid application, tokenId;
        string token;
        using (var scope = ScopeFor(app.Services, tenantId, owner))
        {
            var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
            (await db.Users.SingleAsync(u => u.Id == owner)).GrantSoftwareManager();
            await db.SaveChangesAsync();

            application = await scope.ServiceProvider.GetRequiredService<IProjectService>().CreateAsync(tenantId, "BotWatch", owner);
            var secrets = scope.ServiceProvider.GetRequiredService<ISoftwareSecretService>();
            await secrets.StoreAsync(new StoreSoftwareSecretCommand(tenantId, application, "Production", "Pionex:ApiKey", "pk-value", owner));
            await secrets.SetValueRotationAsync(tenantId, application, "Pionex:ApiKey", "Production",
                new DateTimeOffset(2027, 3, 31, 0, 0, 0, TimeSpan.Zero), "Pionex → API management", owner);

            var issued = await scope.ServiceProvider.GetRequiredService<IAgentTokenService>().IssueAsync(new IssueAgentTokenCommand(
                owner, tenantId, "reader", AgentScopes.ManageApplications, [], ApplicationIds: [application]));
            (token, tokenId) = (issued.Token, issued.TokenId);
        }

        var client = Client(app, token);
        var listed = (await client.GetFromJsonAsync<AgentApplicationResponse>($"{Base}/applications/{application}"))!;
        var production = listed.Keys.Single().Values.Single(v => v.Environment == "Production");
        Assert.AreEqual(new DateTimeOffset(2027, 3, 31, 0, 0, 0, TimeSpan.Zero), production.RotateBy);
        Assert.AreEqual("Pionex → API management", production.RotationNote);

        Assert.AreEqual(HttpStatusCode.OK, (await client.GetAsync($"{Base}/applications/{application}/tokens")).StatusCode);
        Assert.AreEqual(HttpStatusCode.OK, (await client.GetAsync($"{Base}/applications/{application}/statistics")).StatusCode);
        Assert.AreEqual(HttpStatusCode.BadRequest, (await client.GetAsync($"{Base}/applications/{application}/statistics?days=500")).StatusCode);

        using (var scope = ScopeFor(app.Services, tenantId, owner))
        {
            var reads = await scope.ServiceProvider.GetRequiredService<KeywardDbContext>().AuditEntries.AsNoTracking()
                .Where(a => a.TenantId == tenantId && a.ActorTokenId == tokenId && a.Action == AuditAction.Read)
                .Select(a => a.ResourceType)
                .ToListAsync();
            CollectionAssert.IsSubsetOf(new[] { "ApplicationTokens", "ApplicationStatistics" }, reads);
        }
    }

    private static HttpClient Client(Microsoft.AspNetCore.Builder.WebApplication app, string token)
    {
        var client = app.GetTestClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client;
    }
}
