using System.Net.Http.Headers;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Agent;
using Am.Keyward.Mcp;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using static Am.Keyward.Tests.AgentApiTests;

namespace Am.Keyward.Tests;

/// <summary>
/// The MCP tools against the real agent API (in-memory server): the assistant can find, store and change entries,
/// and a secret travels only to the clipboard — no tool answer ever contains a secret value.
/// </summary>
[TestClass]
public class McpToolsTests
{
    [TestMethod, TestCategory("Integration")]
    public async Task Tools_store_find_update_and_reveal_without_ever_answering_with_a_secret()
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
            vault = await vaults.CreateTenantVaultAsync(new CreateTenantVaultCommand(owner, tenantId, "BVD IT – Integrations"));
            await vaults.SetAgentAccessAsync(owner, vault, allowed: true);
        }

        var http = app.GetTestClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer",
            await IssueAsync(app.Services, tenantId, owner, vault, AgentScopes.VaultList | AgentScopes.VaultRead | AgentScopes.VaultWrite | AgentScopes.VaultReveal));
        var clipboard = new FakeClipboard();
        var tools = new KeywardTools(new KeywardAgentClient(http), clipboard);
        var answers = new List<string>();
        async Task<string> Say(Task<string> call) { var answer = await call; answers.Add(answer); return answer; }

        StringAssert.Contains(await Say(tools.ListVaultsAsync(default)), "BVD IT – Integrations");

        var stored = await Say(tools.CreateLoginAsync(vault, "CH-Post API", "https://api.post.ch", "bvd-client", "first-secret", "from the e-mail"));
        StringAssert.StartsWith(stored, "Stored: ");
        StringAssert.Contains(stored, "/amkeyward/e/");
        await Say(tools.CreateItemAsync(vault, "ApiCredential", "DHL key", "dhl-secret"));
        StringAssert.Contains(await Say(tools.CreateItemAsync(vault, "Password", "x", "y")), "400");

        var found = await Say(tools.SearchAsync("post", default));
        StringAssert.Contains(found, "CH-Post API");
        var itemId = Guid.Parse(found.Split('(')[1].Split(',')[0]);

        StringAssert.Contains(await Say(tools.ListItemsAsync(vault, default)), "DHL key");
        var item = await Say(tools.GetItemAsync(itemId, default));
        StringAssert.Contains(item, "User name: bvd-client");

        // Without a version the tool uses the current one; a stale version is refused.
        StringAssert.StartsWith(await Say(tools.UpdateItemAsync(itemId, password: "second-secret")), "Updated: ");
        StringAssert.Contains(await Say(tools.UpdateItemAsync(itemId, versionId: Guid.NewGuid(), password: "third")), "412");

        // Reveal: pending until the person approves, then once — to the clipboard only.
        var requested = await Say(tools.RequestRevealAsync(itemId, "Password", "configure the CH-Post client", default));
        var requestId = Guid.Parse(requested.Split(' ')[2]);
        StringAssert.Contains(await Say(tools.ConsumeRevealAsync(requestId, default)), "Not approved yet");
        Assert.IsNull(clipboard.Value);

        using (var scope = ScopeFor(app.Services, tenantId, owner))
        {
            await scope.ServiceProvider.GetRequiredService<IRevealRequestService>().ApproveAsync(owner, tenantId, requestId);
        }

        StringAssert.Contains(await Say(tools.ConsumeRevealAsync(requestId, default)), "on the clipboard");
        Assert.AreEqual("second-secret", clipboard.Value);
        Assert.AreEqual(KeywardTools.ClipboardLifetime, clipboard.ClearAfter);
        StringAssert.Contains(await Say(tools.ConsumeRevealAsync(requestId, default)), "Consumed");

        foreach (var answer in answers)
        {
            foreach (var secret in new[] { "first-secret", "second-secret", "dhl-secret" })
            {
                Assert.DoesNotContain(secret, answer, $"A tool answered with a secret: {answer}");
            }
        }
    }

    [TestMethod, TestCategory("Unit")]
    public async Task Without_a_clipboard_nothing_is_requested()
    {
        var tools = new KeywardTools(new KeywardAgentClient(new HttpClient { BaseAddress = new Uri("http://unused.invalid") }), new NoSecretClipboard());
        StringAssert.Contains(await tools.RequestRevealAsync(Guid.NewGuid(), "Password", "x", default), "nothing was requested");
        StringAssert.Contains(await tools.ConsumeRevealAsync(Guid.NewGuid(), default), "not available");
    }

    private sealed class FakeClipboard : ISecretClipboard
    {
        public string? Value { get; private set; }

        public TimeSpan? ClearAfter { get; private set; }

        public bool IsAvailable => true;

        public void CopyAndClearLater(string value, TimeSpan clearAfter)
        {
            Value = value;
            ClearAfter = clearAfter;
        }
    }
}
