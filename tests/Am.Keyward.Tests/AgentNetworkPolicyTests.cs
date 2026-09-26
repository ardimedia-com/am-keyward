using System.Net;
using System.Net.Http.Headers;
using Am.Keyward.Api;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain.Agent;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using static Am.Keyward.Tests.AgentApiTests;

namespace Am.Keyward.Tests;

/// <summary>
/// The host-wide network restriction of the agent API: only the configured networks reach the token check; the
/// reverse proxy (svrext03, 172.16.0.93 — everything from the internet arrives with that address) stays outside.
/// </summary>
[TestClass]
public class AgentNetworkPolicyTests
{
    private const string Lan = "10.1.0.0/23";

    [TestMethod, TestCategory("Integration")]
    public async Task Only_the_allowed_networks_reach_the_agent_api()
    {
        await using var app = await StartAsync(agentOptions: o => o.AllowedNetworks = Lan);
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
            vault = await vaults.CreateTenantVaultAsync(new CreateTenantVaultCommand(owner, tenantId, "Integrations"));
            await vaults.SetAgentAccessAsync(owner, vault, allowed: true);
        }

        var token = await IssueAsync(app.Services, tenantId, owner, vault, AgentScopes.VaultList);

        async Task<HttpStatusCode> PingFrom(string? ip, string bearer)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "/keyward/api/v1/agent/ping");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
            if (ip is not null)
            {
                request.Headers.Add(TestClientIpHeader, ip);
            }

            return (await app.GetTestClient().SendAsync(request)).StatusCode;
        }

        Assert.AreEqual(HttpStatusCode.NoContent, await PingFrom("10.1.0.26", token), "A LAN client with a valid token.");
        Assert.AreEqual(HttpStatusCode.NoContent, await PingFrom("::ffff:10.1.1.112", token), "IPv4-mapped IPv6 from the LAN.");
        Assert.AreEqual(HttpStatusCode.Forbidden, await PingFrom("172.16.0.93", token), "Through the reverse proxy — i.e. from the internet.");
        Assert.AreEqual(HttpStatusCode.Forbidden, await PingFrom("10.1.2.1", token), "Just outside the LAN range.");
        Assert.AreEqual(HttpStatusCode.Forbidden, await PingFrom(null, token), "Unknown client address.");

        // From outside, even a guessed token is refused as a network matter (403, not 401) — no token is looked up.
        Assert.AreEqual(HttpStatusCode.Forbidden, await PingFrom("172.16.0.93", "amkwa_000000000000_" + new string('0', 64)));
        Assert.AreEqual(HttpStatusCode.Unauthorized, await PingFrom("10.1.0.26", "amkwa_000000000000_" + new string('0', 64)));
    }

    [TestMethod, TestCategory("Unit")]
    public void Policy_parses_cidr_lists_and_rejects_nonsense()
    {
        var policy = new AgentNetworkPolicy("10.1.0.0/23; 192.168.10.0/24");
        Assert.IsTrue(policy.IsRestricted);
        Assert.IsTrue(policy.Allows(IPAddress.Parse("192.168.10.5")));
        Assert.IsFalse(policy.Allows(IPAddress.Parse("192.168.11.5")));

        var open = new AgentNetworkPolicy(null);
        Assert.IsFalse(open.IsRestricted);
        Assert.IsTrue(open.Allows(null));

        Assert.ThrowsExactly<ArgumentException>(() => new AgentNetworkPolicy("10.1.0.0/23, lan"));
    }
}
