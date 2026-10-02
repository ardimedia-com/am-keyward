using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Am.Keyward.Contracts;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Agent;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Am.Keyward.Tests;

/// <summary>
/// Decision T12 B (2026-10-02): a personal vault can be opened to AI agents like a team vault — for its owner's tokens
/// only, under the same rules (allowlist or «all», the vault's agent flag).
/// </summary>
[TestClass]
public class AgentPersonalVaultTests
{
    [TestMethod, TestCategory("Integration")]
    public async Task An_opened_personal_vault_is_reachable_by_its_owners_token_only()
    {
        await using var app = await AgentApiTests.StartAsync();
        if (app is null)
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var services = app.Services;
        var tenantId = Guid.NewGuid();
        var owner = Guid.NewGuid();
        var colleague = Guid.NewGuid();
        await AgentApiTests.SeedTenantAsync(services, tenantId, owner);
        await AgentApiTests.SeedTenantAsync(services, Guid.NewGuid(), colleague);

        Guid personal, closed;
        using (var scope = AgentApiTests.ScopeFor(services, tenantId, owner))
        {
            var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
            personal = await vaults.CreatePersonalVaultAsync(new CreatePersonalVaultCommand(owner, "Privat"));
            closed = await vaults.CreatePersonalVaultAsync(new CreatePersonalVaultCommand(owner, "Geschlossen"));
            await vaults.SetAgentAccessAsync(owner, personal, allowed: true);

            // A closed personal vault cannot be put on a token.
            await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => scope.ServiceProvider.GetRequiredService<IAgentTokenService>()
                .IssueAsync(new IssueAgentTokenCommand(owner, tenantId, "closed", AgentScopes.VaultList, [closed])));
        }

        // Nobody else can put it on their token.
        using (var scope = AgentApiTests.ScopeFor(services, tenantId, colleague))
        {
            await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => scope.ServiceProvider.GetRequiredService<IAgentTokenService>()
                .IssueAsync(new IssueAgentTokenCommand(colleague, tenantId, "theirs", AgentScopes.VaultList, [personal])));
        }

        var client = app.GetTestClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer",
            await AgentApiTests.IssueAsync(services, tenantId, owner, personal, AgentScopes.VaultList | AgentScopes.VaultWrite));

        var list = await client.GetFromJsonAsync<List<AgentVaultResponse>>("/keyward/api/v1/agent/vaults");
        CollectionAssert.AreEqual(new[] { personal }, list!.Select(v => v.Id).ToArray());

        var created = await client.PostAsJsonAsync($"/keyward/api/v1/agent/vaults/{personal}/items",
            new AgentCreateItemRequest("Login", "Router", Url: "https://192.168.1.1", Username: "admin"));
        Assert.AreEqual(HttpStatusCode.Created, created.StatusCode);
        Assert.AreEqual(HttpStatusCode.NotFound, (await client.GetAsync($"/keyward/api/v1/agent/vaults/{closed}/tree")).StatusCode);

        // «All vaults opened to agents» reaches it too; closing the vault stops every token at once.
        using (var scope = AgentApiTests.ScopeFor(services, tenantId, owner))
        {
            var issued = await scope.ServiceProvider.GetRequiredService<IAgentTokenService>().IssueAsync(new IssueAgentTokenCommand(
                owner, tenantId, "all", AgentScopes.VaultList, [], AllAgentVaults: true));
            var access = scope.ServiceProvider.GetRequiredService<IAgentVaultAccess>();
            Assert.IsTrue(await access.IsVaultAllowedAsync(issued.TokenId, personal, AgentScopes.VaultList, Permission.Read));
            Assert.IsFalse(await access.IsVaultAllowedAsync(issued.TokenId, closed, AgentScopes.VaultList, Permission.Read));

            await scope.ServiceProvider.GetRequiredService<IVaultService>().SetAgentAccessAsync(owner, personal, allowed: false);
            Assert.IsFalse(await access.IsVaultAllowedAsync(issued.TokenId, personal, AgentScopes.VaultList, Permission.Read));
        }

        Assert.AreEqual(HttpStatusCode.NotFound, (await client.GetAsync($"/keyward/api/v1/agent/vaults/{personal}/tree")).StatusCode);
    }
}
