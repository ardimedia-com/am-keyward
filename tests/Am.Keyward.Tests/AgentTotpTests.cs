using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Am.Keyward.Contracts;
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
/// Decisions T15 A / T16 A+B (2026-10-06): an agent may store a Login's 2FA key (never read it back), sees whether an
/// entry has one, and gets a one-time code either through an approved reveal request or — with the permission
/// «one-time codes» — directly, each code audited.
/// </summary>
[TestClass]
public class AgentTotpTests
{
    private const string Secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

    // The code now or of the period just ended — the request may have crossed a 30-second boundary.
    private static string[] CurrentCodes() =>
        [Totp.Generate(Secret, DateTimeOffset.UtcNow).Code, Totp.Generate(Secret, DateTimeOffset.UtcNow.AddSeconds(-30)).Code];

    [TestMethod, TestCategory("Integration")]
    public async Task An_agent_stores_a_2FA_key_and_gets_codes_only_as_permitted()
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

        Guid vault;
        using (var scope = ScopeFor(services, tenantId, owner))
        {
            var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
            vault = await vaults.CreateTenantVaultAsync(new CreateTenantVaultCommand(owner, tenantId, "KI-Tresor"));
            await vaults.SetAgentAccessAsync(owner, vault, allowed: true);
        }

        var writer = app.GetTestClient();
        writer.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer",
            await IssueAsync(services, tenantId, owner, vault, AgentScopes.VaultList | AgentScopes.VaultRead | AgentScopes.VaultWrite | AgentScopes.VaultReveal));

        // An unreadable key is refused with a reason; a good one is stored and never echoed.
        var refused = await writer.PostAsJsonAsync($"/keyward/api/v1/agent/vaults/{vault}/items",
            new AgentCreateItemRequest("Login", "DHL MyBill", Url: "https://mybill.dhl.com", Username: "bvd@bvd.li", Totp: "not-a-key"));
        Assert.AreEqual(HttpStatusCode.BadRequest, refused.StatusCode);

        var created = await writer.PostAsJsonAsync($"/keyward/api/v1/agent/vaults/{vault}/items",
            new AgentCreateItemRequest("Login", "DHL MyBill", Url: "https://mybill.dhl.com", Username: "bvd@bvd.li", Password: "pw", Totp: Secret));
        Assert.AreEqual(HttpStatusCode.Created, created.StatusCode);
        var login = (await created.Content.ReadFromJsonAsync<AgentItemWrittenResponse>())!.Id;
        Assert.DoesNotContain(Secret, await created.Content.ReadAsStringAsync());

        var item = await writer.GetFromJsonAsync<AgentItemResponse>($"/keyward/api/v1/agent/items/{login}");
        Assert.IsTrue(item!.HasTotp);
        Assert.DoesNotContain(Secret, await (await writer.GetAsync($"/keyward/api/v1/agent/items/{login}")).Content.ReadAsStringAsync());

        // Without «one-time codes» there is no direct code — only the reveal request (T16 A).
        Assert.AreEqual(HttpStatusCode.NotFound, (await writer.PostAsync($"/keyward/api/v1/agent/items/{login}/totp-code", null)).StatusCode);

        var request = await (await writer.PostAsJsonAsync($"/keyward/api/v1/agent/items/{login}/reveal-requests",
            new AgentRevealRequestBody("Totp", "sign in to DHL MyBill"))).Content.ReadFromJsonAsync<AgentRevealStateResponse>();
        using (var scope = ScopeFor(services, tenantId, owner))
        {
            await scope.ServiceProvider.GetRequiredService<IRevealRequestService>().ApproveAsync(owner, tenantId, request!.Id);
        }

        var revealed = await (await writer.PostAsync($"/keyward/api/v1/agent/reveal-requests/{request!.Id}/consume", null))
            .Content.ReadFromJsonAsync<AgentRevealValueResponse>();
        Assert.AreEqual("Totp", revealed!.Field);
        CollectionAssert.Contains(CurrentCodes(), revealed.Value, "the code of this moment, never the key");

        // With the permission the code comes directly (T16 B), audited per call.
        var direct = app.GetTestClient();
        direct.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer",
            await IssueAsync(services, tenantId, owner, vault, AgentScopes.VaultList | AgentScopes.TotpCodes));
        var response = await direct.PostAsync($"/keyward/api/v1/agent/items/{login}/totp-code", null);
        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        Assert.IsTrue(response.Headers.CacheControl?.NoStore);
        var code = await response.Content.ReadFromJsonAsync<AgentTotpCodeResponse>();
        CollectionAssert.Contains(CurrentCodes(), code!.Code);
        Assert.IsInRange(0, 30, code.SecondsLeft);

        using (var scope = ScopeFor(services, tenantId, owner))
        {
            var audit = await scope.ServiceProvider.GetRequiredService<KeywardDbContext>().AuditEntries.AsNoTracking()
                .Where(a => a.TenantId == tenantId && a.ResourceId == login && a.ResourceType == "VaultItemTotp")
                .ToListAsync();
            Assert.AreEqual(ActorKind.Agent, audit.Single().ActorKind);
            Assert.AreEqual(AuditAction.Reveal, audit.Single().Action);
        }

        // A key can be replaced or removed field by field; the other fields stay.
        var version = item.VersionId;
        var patch = new HttpRequestMessage(HttpMethod.Patch, $"/keyward/api/v1/agent/items/{login}")
        {
            Content = JsonContent.Create(new AgentUpdateItemRequest(Totp: "")),
        };
        patch.Headers.IfMatch.Add(new EntityTagHeaderValue($"\"{version}\""));
        Assert.AreEqual(HttpStatusCode.OK, (await writer.SendAsync(patch)).StatusCode);
        var after = await writer.GetFromJsonAsync<AgentItemResponse>($"/keyward/api/v1/agent/items/{login}");
        Assert.IsFalse(after!.HasTotp);
        Assert.AreEqual("bvd@bvd.li", after.Username);
        Assert.AreEqual(HttpStatusCode.BadRequest, (await direct.PostAsync($"/keyward/api/v1/agent/items/{login}/totp-code", null)).StatusCode);
    }
}
