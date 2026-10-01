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
/// Decisions T7 A and T8 A (2026-10-01): an issued token can be changed by its owner — the token value stays — and a
/// token can reach «all team vaults opened to agents» and «all applications», today's and future ones. The vault flag
/// and the user's own grant still decide for every vault.
/// </summary>
[TestClass]
public class AgentTokenEditAndWildcardTests
{
    private const string Base = "/keyward/api/v1/agent";

    [TestMethod, TestCategory("Integration")]
    public async Task Wildcards_reach_future_vaults_and_applications_but_never_past_the_vault_flag()
    {
        await using var app = await StartAsync();
        if (app is null)
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var (tenantId, owner) = await SeedManagerAsync(app.Services);
        var other = Guid.NewGuid();
        string token;
        using (var scope = ScopeFor(app.Services, tenantId, owner))
        {
            token = (await scope.ServiceProvider.GetRequiredService<IAgentTokenService>().IssueAsync(new IssueAgentTokenCommand(
                owner, tenantId, "everything", AgentScopes.VaultList | AgentScopes.ManageApplications, [],
                AllAgentVaults: true, AllApplications: true))).Token;
        }

        // Created AFTER the token was issued.
        Guid opened, closed, application;
        using (var scope = ScopeFor(app.Services, tenantId, owner))
        {
            var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
            opened = await vaults.CreateTenantVaultAsync(new CreateTenantVaultCommand(owner, tenantId, "Opened later"));
            closed = await vaults.CreateTenantVaultAsync(new CreateTenantVaultCommand(owner, tenantId, "Never opened"));
            await vaults.SetAgentAccessAsync(owner, opened, allowed: true);
            application = await scope.ServiceProvider.GetRequiredService<IProjectService>().CreateAsync(tenantId, "Created by a person later", owner);
        }

        var client = Client(app, token);
        var reachable = (await client.GetFromJsonAsync<List<AgentVaultResponse>>($"{Base}/vaults"))!.Select(v => v.Id).ToList();
        CollectionAssert.Contains(reachable, opened);
        CollectionAssert.DoesNotContain(reachable, closed);
        Assert.AreEqual(HttpStatusCode.NotFound, (await client.GetAsync($"{Base}/vaults/{closed}/tree")).StatusCode);
        Assert.AreEqual(HttpStatusCode.OK, (await client.GetAsync($"{Base}/applications/{application}")).StatusCode);

        var info = (await client.GetFromJsonAsync<AgentTokenInfoResponse>($"{Base}/token"))!;
        Assert.IsTrue(info.AllAgentVaults);
        Assert.IsTrue(info.AllApplications);

        // A wildcard is no way around the vault's own rules: a vault opened by someone who did not share it with the
        // token's user stays out of reach.
        Guid foreign;
        await SeedUserAsync(app.Services, tenantId, other);
        using (var scope = ScopeFor(app.Services, tenantId, other))
        {
            var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
            foreign = await vaults.CreateTenantVaultAsync(new CreateTenantVaultCommand(other, tenantId, "Someone else's"));
            await vaults.SetAgentAccessAsync(other, foreign, allowed: true);
        }

        Assert.AreEqual(HttpStatusCode.NotFound, (await client.GetAsync($"{Base}/vaults/{foreign}/tree")).StatusCode);
    }

    [TestMethod, TestCategory("Integration")]
    public async Task The_owner_changes_a_token_and_the_value_keeps_working()
    {
        await using var app = await StartAsync();
        if (app is null)
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var (tenantId, owner) = await SeedManagerAsync(app.Services);
        Guid first, second, application;
        IssuedAgentToken issued;
        using (var scope = ScopeFor(app.Services, tenantId, owner))
        {
            var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
            first = await vaults.CreateTenantVaultAsync(new CreateTenantVaultCommand(owner, tenantId, "First"));
            second = await vaults.CreateTenantVaultAsync(new CreateTenantVaultCommand(owner, tenantId, "Second"));
            await vaults.SetAgentAccessAsync(owner, first, allowed: true);
            await vaults.SetAgentAccessAsync(owner, second, allowed: true);
            application = await scope.ServiceProvider.GetRequiredService<IProjectService>().CreateAsync(tenantId, "BotWatch", owner);
            issued = await scope.ServiceProvider.GetRequiredService<IAgentTokenService>().IssueAsync(new IssueAgentTokenCommand(
                owner, tenantId, "laptop", AgentScopes.VaultList, [first]));
        }

        var client = Client(app, issued.Token);
        Assert.AreEqual(HttpStatusCode.OK, (await client.GetAsync($"{Base}/vaults/{first}/tree")).StatusCode);
        Assert.AreEqual(HttpStatusCode.NotFound, (await client.GetAsync($"{Base}/vaults/{second}/tree")).StatusCode);
        Assert.AreEqual(HttpStatusCode.Forbidden, (await client.GetAsync($"{Base}/applications")).StatusCode);

        using (var scope = ScopeFor(app.Services, tenantId, owner))
        {
            var tokens = scope.ServiceProvider.GetRequiredService<IAgentTokenService>();

            // The same rules as at issue.
            await Assert.ThrowsExactlyAsync<ArgumentException>(() => tokens.UpdateAsync(new UpdateAgentTokenCommand(
                owner, tenantId, issued.TokenId, "laptop", AgentScopes.VaultList, [])));

            await tokens.UpdateAsync(new UpdateAgentTokenCommand(
                owner, tenantId, issued.TokenId, "laptop-2", AgentScopes.VaultList | AgentScopes.ManageApplications, [second],
                ApplicationIds: [application]));

            var listed = (await tokens.ListAsync(owner, tenantId)).Single(t => t.Id == issued.TokenId);
            Assert.AreEqual("laptop-2", listed.Name);
            CollectionAssert.AreEqual(new[] { second }, listed.VaultIds.ToArray());
            CollectionAssert.AreEqual(new[] { application }, listed.ApplicationIds.ToArray());
        }

        // Same token value, new reach.
        Assert.AreEqual(HttpStatusCode.NotFound, (await client.GetAsync($"{Base}/vaults/{first}/tree")).StatusCode);
        Assert.AreEqual(HttpStatusCode.OK, (await client.GetAsync($"{Base}/vaults/{second}/tree")).StatusCode);
        Assert.AreEqual(HttpStatusCode.OK, (await client.GetAsync($"{Base}/applications/{application}")).StatusCode);

        // Only its owner may change it; a revoked token cannot be changed; every change is audited.
        var stranger = Guid.NewGuid();
        await SeedUserAsync(app.Services, tenantId, stranger);
        using (var scope = ScopeFor(app.Services, tenantId, stranger))
        {
            await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => scope.ServiceProvider.GetRequiredService<IAgentTokenService>()
                .UpdateAsync(new UpdateAgentTokenCommand(stranger, tenantId, issued.TokenId, "mine", AgentScopes.VaultList, [second])));
        }

        using (var scope = ScopeFor(app.Services, tenantId, owner))
        {
            var tokens = scope.ServiceProvider.GetRequiredService<IAgentTokenService>();
            await tokens.RevokeAsync(owner, tenantId, issued.TokenId);
            await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => tokens.UpdateAsync(new UpdateAgentTokenCommand(
                owner, tenantId, issued.TokenId, "laptop", AgentScopes.VaultList, [first])));

            var updates = await scope.ServiceProvider.GetRequiredService<KeywardDbContext>().AuditEntries.AsNoTracking()
                .CountAsync(a => a.TenantId == tenantId && a.ResourceType == "AgentToken" && a.ResourceId == issued.TokenId && a.Action == AuditAction.Update);
            Assert.AreEqual(1, updates);
        }
    }

    private static async Task<(Guid TenantId, Guid Owner)> SeedManagerAsync(IServiceProvider services)
    {
        var tenantId = Guid.NewGuid();
        var owner = Guid.NewGuid();
        await SeedTenantAsync(services, tenantId, owner);
        using var scope = ScopeFor(services, tenantId, owner);
        var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
        (await db.Users.SingleAsync(u => u.Id == owner)).GrantSoftwareManager();
        await db.SaveChangesAsync();
        return (tenantId, owner);
    }

    private static async Task SeedUserAsync(IServiceProvider services, Guid tenantId, Guid userId)
    {
        using var scope = ScopeFor(services, tenantId, userId);
        var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
        db.Users.Add(new Am.Keyward.Core.Domain.Identity.AppUser(userId, issuer: null, externalId: $"user-{userId:N}", displayName: "other", isSystemAdmin: false, DateTimeOffset.UtcNow));
        db.TenantMemberships.Add(new Am.Keyward.Core.Domain.Identity.TenantMembership(Guid.NewGuid(), tenantId, userId, TenantRole.Member, DateTimeOffset.UtcNow));
        await db.SaveChangesAsync();
    }

    private static HttpClient Client(Microsoft.AspNetCore.Builder.WebApplication app, string token)
    {
        var client = app.GetTestClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client;
    }
}
