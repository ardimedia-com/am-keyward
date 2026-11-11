using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Am.Keyward.Contracts;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Agent;
using Am.Keyward.Infrastructure.Statistics;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using static Am.Keyward.Tests.AgentApiTests;

namespace Am.Keyward.Tests;

/// <summary>
/// Review 3, cross-area wiring: an authenticated agent call records the token's last use (shown in the token list),
/// and an agent over its cap of undecided reveal requests gets 429 with a problem detail instead of 500.
/// </summary>
[TestClass]
public class Review3WiringTests
{
    [TestMethod, TestCategory("Integration")]
    public async Task An_agent_call_records_the_tokens_last_use_and_address_in_the_token_list()
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
        Guid vault;
        using (var scope = ScopeFor(app.Services, tenantId, owner))
        {
            var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
            vault = await vaults.CreateTenantVaultAsync(new CreateTenantVaultCommand(owner, tenantId, "v"));
            await vaults.SetAgentAccessAsync(owner, vault, allowed: true);
        }

        var token = await IssueAsync(app.Services, tenantId, owner, vault, AgentScopes.VaultList);
        using (var scope = ScopeFor(app.Services, tenantId, owner))
        {
            var before = (await scope.ServiceProvider.GetRequiredService<IAgentTokenService>().ListAsync(owner, tenantId)).Single();
            Assert.IsNull(before.LastUsedAt, "a token nobody used has no last use");
        }

        using var request = new HttpRequestMessage(HttpMethod.Get, $"{Am.Keyward.Api.KeywardAgentApi.DefaultPrefix}/ping");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        request.Headers.Add(TestClientIpHeader, "10.20.30.40");
        Assert.AreEqual(HttpStatusCode.NoContent, (await app.GetTestClient().SendAsync(request)).StatusCode);

        // The host's hosted services are removed in tests; run one flush of the same singletons by hand.
        var flush = ActivatorUtilities.CreateInstance<TokenAccessFlushService>(app.Services);
        await flush.FlushAsync(statisticsEnabled: true, CancellationToken.None);

        using (var scope = ScopeFor(app.Services, tenantId, owner))
        {
            var after = (await scope.ServiceProvider.GetRequiredService<IAgentTokenService>().ListAsync(owner, tenantId)).Single();
            Assert.IsNotNull(after.LastUsedAt);
            Assert.AreEqual("10.20.30.40", after.LastUsedIp);
        }
    }

    [TestMethod, TestCategory("Integration")]
    public async Task An_agent_over_its_cap_of_undecided_reveal_requests_gets_429_not_500()
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
        Guid vault;
        var items = new List<Guid>();
        using (var scope = ScopeFor(app.Services, tenantId, owner))
        {
            var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
            vault = await vaults.CreateTenantVaultAsync(new CreateTenantVaultCommand(owner, tenantId, "v"));
            await vaults.SetAgentAccessAsync(owner, vault, allowed: true);
            for (var i = 0; i <= RevealRequestLimits.MaxPendingPerToken; i++)
            {
                items.Add(await vaults.AddItemAsync(new AddVaultItemCommand(owner, vault, null, ItemType.Generic, $"item {i}", "v")));
            }
        }

        var client = app.GetTestClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            "Bearer", await IssueAsync(app.Services, tenantId, owner, vault, AgentScopes.VaultList | AgentScopes.VaultReveal));

        for (var i = 0; i < RevealRequestLimits.MaxPendingPerToken; i++)
        {
            Assert.AreEqual(HttpStatusCode.Accepted,
                (await client.PostAsJsonAsync($"/keyward/api/v1/agent/items/{items[i]}/reveal-requests", new AgentRevealRequestBody("Value", "setup"))).StatusCode);
        }

        var refused = await client.PostAsJsonAsync($"/keyward/api/v1/agent/items/{items[^1]}/reveal-requests", new AgentRevealRequestBody("Value", "setup"));
        Assert.AreEqual(HttpStatusCode.TooManyRequests, refused.StatusCode);
        Assert.AreEqual("application/problem+json", refused.Content.Headers.ContentType?.MediaType);
        var problem = await refused.Content.ReadFromJsonAsync<ProblemDetails>();
        Assert.AreEqual(429, problem!.Status);
        Assert.IsFalse(string.IsNullOrWhiteSpace(problem.Title));
    }
}
