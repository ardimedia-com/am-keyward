using System.Security.Cryptography;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Agent;
using Am.Keyward.Core.Domain.Identity;
using Am.Keyward.Core.Domain.ValueObjects;
using Am.Keyward.Infrastructure;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Am.Keyward.Tests;

/// <summary>
/// Agent tokens that manage applications: who may hand out <see cref="AgentScopes.ManageApplications"/>, what the
/// application allowlist accepts, and that whatever an agent creates remembers the token (the basis for letting it
/// rename or delete only its own, still empty, placeholders).
/// </summary>
[TestClass]
public class AgentApplicationTokenTests
{
    private static readonly string ConnectionString = TestConfig.ConnectionString;

    [TestMethod, TestCategory("Integration")]
    public async Task Issuance_rules_for_managing_applications()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var tenantId = Guid.NewGuid();
        var admin = Guid.NewGuid();
        var member = Guid.NewGuid();
        await SeedTenantAsync(provider, tenantId, (admin, TenantRole.TenantAdmin), (member, TenantRole.Member));

        using var scope = ScopeFor(provider, tenantId, admin);
        var tokens = scope.ServiceProvider.GetRequiredService<IAgentTokenService>();
        var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
        var projects = scope.ServiceProvider.GetRequiredService<IProjectService>();

        var app = await projects.CreateAsync(tenantId, "BotWatch", admin);
        var vault = await vaults.CreateTenantVaultAsync(new CreateTenantVaultCommand(admin, tenantId, "KI-Tresor"));
        await vaults.SetAgentAccessAsync(admin, vault, allowed: true);

        // The permission needs a target: an application or the right to create new ones.
        await Assert.ThrowsExactlyAsync<ArgumentException>(() => tokens.IssueAsync(Manage(admin, tenantId)));

        // Applications and the create flag need the permission; vaults need a vault permission.
        await Assert.ThrowsExactlyAsync<ArgumentException>(() => tokens.IssueAsync(
            new IssueAgentTokenCommand(admin, tenantId, "t", AgentScopes.VaultList, [vault], ApplicationIds: [app])));
        await Assert.ThrowsExactlyAsync<ArgumentException>(() => tokens.IssueAsync(
            new IssueAgentTokenCommand(admin, tenantId, "t", AgentScopes.VaultList, [vault], MayCreateApplications: true)));
        await Assert.ThrowsExactlyAsync<ArgumentException>(() => tokens.IssueAsync(Manage(admin, tenantId, create: true) with { VaultIds = [vault] }));
        await Assert.ThrowsExactlyAsync<ArgumentException>(() => tokens.IssueAsync(
            new IssueAgentTokenCommand(admin, tenantId, "t", AgentScopes.VaultList, [])));

        // Only applications of the token's own tenant can be allowlisted.
        await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => tokens.IssueAsync(Manage(admin, tenantId, Guid.NewGuid())));

        // A plain member cannot hand the permission to an agent, not even for creating new applications.
        using (var memberScope = ScopeFor(provider, tenantId, member))
        {
            await Assert.ThrowsExactlyAsync<UnauthorizedAccessException>(() =>
                memberScope.ServiceProvider.GetRequiredService<IAgentTokenService>().IssueAsync(Manage(member, tenantId, create: true)));
        }

        // Applications only, no vault: a valid token.
        var issued = await tokens.IssueAsync(Manage(admin, tenantId, app) with { MayCreateApplications = true });
        var listed = (await tokens.ListAsync(admin, tenantId)).Single(t => t.Id == issued.TokenId);
        Assert.AreEqual(AgentScopes.ManageApplications, listed.Scopes);
        CollectionAssert.AreEqual(new[] { app }, listed.ApplicationIds.ToArray());
        Assert.IsTrue(listed.MayCreateApplications);
        Assert.IsEmpty(listed.VaultIds);

        // Vault and application permissions combine on one token.
        var combined = await tokens.IssueAsync(Manage(admin, tenantId, app) with { Scopes = AgentScopes.ManageApplications | AgentScopes.VaultList, VaultIds = [vault] });
        var combinedListed = (await tokens.ListAsync(admin, tenantId)).Single(t => t.Id == combined.TokenId);
        CollectionAssert.AreEqual(new[] { vault }, combinedListed.VaultIds.ToArray());
        Assert.IsFalse(combinedListed.MayCreateApplications);

        // Deleting the application takes it off every allowlist.
        await projects.DeleteAsync(tenantId, app, admin);
        Assert.IsEmpty((await tokens.ListAsync(admin, tenantId)).Single(t => t.Id == issued.TokenId).ApplicationIds);
    }

    [TestMethod, TestCategory("Integration")]
    public async Task What_an_agent_creates_remembers_the_token()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var tenantId = Guid.NewGuid();
        var admin = Guid.NewGuid();
        await SeedTenantAsync(provider, tenantId, (admin, TenantRole.TenantAdmin));

        IssuedAgentToken issued;
        Guid byPerson;
        using (var scope = ScopeFor(provider, tenantId, admin))
        {
            issued = await scope.ServiceProvider.GetRequiredService<IAgentTokenService>().IssueAsync(Manage(admin, tenantId, create: true));
            byPerson = await scope.ServiceProvider.GetRequiredService<IProjectService>().CreateAsync(tenantId, "by-person", admin);
            await scope.ServiceProvider.GetRequiredService<ISoftwareSecretService>().CreateSecretAsync(tenantId, byPerson, "Person:Key", admin);
        }

        Guid byAgent;
        using (var scope = ScopeFor(provider, tenantId, admin))
        {
            // As the agent authentication handler does for every agent request.
            scope.ServiceProvider.GetRequiredService<IActorScopeSetter>().SetActor(ActorKind.Agent, issued.TokenId);
            byAgent = await scope.ServiceProvider.GetRequiredService<IProjectService>().CreateAsync(tenantId, "by-agent", admin);
            var secrets = scope.ServiceProvider.GetRequiredService<ISoftwareSecretService>();
            await secrets.CreateSecretAsync(tenantId, byAgent, "PionexOwnerBotWatch:ApiKey", admin);
            await secrets.StoreAsync(new StoreSoftwareSecretCommand(
                tenantId, byAgent, EnvironmentName.Production.Value, "PionexOwnerBotWatch:ApiSecret", "value", admin));
        }

        using var check = ScopeFor(provider, tenantId, admin);
        var db = check.ServiceProvider.GetRequiredService<KeywardDbContext>();
        var projects = await db.Projects.AsNoTracking().Where(p => p.Id == byAgent || p.Id == byPerson).ToListAsync();
        Assert.AreEqual(issued.TokenId, projects.Single(p => p.Id == byAgent).CreatedByAgentTokenId);
        Assert.IsNull(projects.Single(p => p.Id == byPerson).CreatedByAgentTokenId);

        var secretsByProject = await db.SoftwareSecrets.AsNoTracking().Where(s => s.ProjectId == byAgent || s.ProjectId == byPerson).ToListAsync();
        Assert.IsTrue(secretsByProject.Where(s => s.ProjectId == byAgent).All(s => s.CreatedByAgentTokenId == issued.TokenId));
        Assert.HasCount(2, secretsByProject.Where(s => s.ProjectId == byAgent));
        Assert.IsNull(secretsByProject.Single(s => s.ProjectId == byPerson).CreatedByAgentTokenId);
    }

    private static IssueAgentTokenCommand Manage(Guid userId, Guid tenantId, Guid? applicationId = null, bool create = false) =>
        new(userId, tenantId, $"agent-{Guid.NewGuid():N}", AgentScopes.ManageApplications, [],
            ApplicationIds: applicationId is { } id ? [id] : [], MayCreateApplications: create);

    private static async Task SeedTenantAsync(ServiceProvider provider, Guid tenantId, params (Guid UserId, TenantRole Role)[] users)
    {
        using var scope = provider.CreateScope();
        scope.ServiceProvider.GetRequiredService<ITenantScopeSetter>().SetTenant(tenantId);
        var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
        db.Tenants.Add(new Tenant(tenantId, "agent-apps-test", isSystemTenant: false, DateTimeOffset.UtcNow));
        foreach (var (userId, role) in users)
        {
            db.Users.Add(new AppUser(userId, issuer: null, externalId: userId.ToString(), displayName: $"user-{userId:N}", isSystemAdmin: false, DateTimeOffset.UtcNow));
            db.TenantMemberships.Add(new TenantMembership(Guid.NewGuid(), tenantId, userId, role, DateTimeOffset.UtcNow));
        }

        await db.SaveChangesAsync();
    }

    private static IServiceScope ScopeFor(ServiceProvider provider, Guid tenantId, Guid userId)
    {
        var scope = provider.CreateScope();
        scope.ServiceProvider.GetRequiredService<ITenantScopeSetter>().SetTenant(tenantId);
        scope.ServiceProvider.GetRequiredService<IUserScopeSetter>().SetUser(userId);
        return scope;
    }

    private static ServiceProvider BuildProvider()
    {
        var services = new ServiceCollection();
        services.AddKeyward(ConnectionString, RandomNumberGenerator.GetBytes(32), "test-kek:v1");
        return services.BuildServiceProvider();
    }

    private static async Task<bool> CanConnectAsync(ServiceProvider provider)
    {
        using var scope = provider.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<KeywardDbContext>().Database.CanConnectAsync();
    }
}
