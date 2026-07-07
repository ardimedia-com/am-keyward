using System.Security.Cryptography;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Identity;
using Am.Keyward.Core.Domain.ValueObjects;
using Am.Keyward.Infrastructure;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Am.Keyward.Tests;

/// <summary>
/// Application ("project") management against a real SQL Server: create with the default environments,
/// rename with a uniqueness guard, tenant-admin gating, and delete cascading environments + secrets +
/// tokens. Skips (inconclusive) when no DB is reachable.
/// </summary>
[TestClass]
public class ProjectServiceTests
{
    private static readonly string ConnectionString = TestConfig.ConnectionString;

    [TestMethod, TestCategory("Integration")]
    public async Task Create_rename_and_authorization_guards()
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

        using var scope = ScopeFor(provider, admin, tenantId);
        var projects = scope.ServiceProvider.GetRequiredService<IProjectService>();

        // Create → listed, with the full default environment set so secrets/tokens have a target.
        var appId = await projects.CreateAsync(tenantId, "webshop", admin);
        var listed = (await projects.ListAsync(tenantId)).Single(p => p.Id == appId);
        Assert.AreEqual("webshop", listed.Name);
        Assert.AreEqual(EnvironmentName.DefaultSet.Count(), listed.EnvironmentCount);
        Assert.AreEqual(0, listed.SecretCount);
        // One pending app token per environment is created automatically.
        Assert.AreEqual(EnvironmentName.DefaultSet.Count(), listed.TokenCount);

        // Duplicate names are rejected; rename works and re-checks uniqueness.
        await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => projects.CreateAsync(tenantId, "webshop", admin));
        await projects.RenameAsync(tenantId, appId, "shop", admin);
        Assert.IsTrue((await projects.ListAsync(tenantId)).Any(p => p.Name == "shop"));

        // A plain member may list but not manage.
        using var memberScope = ScopeFor(provider, member, tenantId);
        var memberProjects = memberScope.ServiceProvider.GetRequiredService<IProjectService>();
        Assert.IsTrue((await memberProjects.ListAsync(tenantId)).Any(p => p.Id == appId));
        await Assert.ThrowsExactlyAsync<UnauthorizedAccessException>(() => memberProjects.CreateAsync(tenantId, "backend", member));
        await Assert.ThrowsExactlyAsync<UnauthorizedAccessException>(() => memberProjects.DeleteAsync(tenantId, appId, member));
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Pending_tokens_follow_the_environment_lifecycle()
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

        using var scope = ScopeFor(provider, admin, tenantId);
        var projects = scope.ServiceProvider.GetRequiredService<IProjectService>();
        var tokens = scope.ServiceProvider.GetRequiredService<ISoftwareClientTokenService>();
        var secrets = scope.ServiceProvider.GetRequiredService<ISoftwareSecretService>();

        // Creating the application creates one pending token per environment — placeholders, not credentials.
        var appId = await projects.CreateAsync(tenantId, "bird", admin);
        var pending = await tokens.ListAsync(tenantId, appId);
        Assert.AreEqual(EnvironmentName.DefaultSet.Count(), pending.Count);
        Assert.IsTrue(pending.All(t => !t.HasSecret && !t.IsActive && t.RevokedAt is null));
        Assert.IsTrue(pending.Any(t => t.Name == "bird-production"));

        // Minting the first value turns the placeholder into a working credential.
        var prodPending = pending.Single(t => t.Name == "bird-production");
        var minted = await tokens.RotateAsync(tenantId, prodPending.Id, DateTimeOffset.UtcNow.AddDays(30), admin);
        using (var authScope = provider.CreateScope())
        {
            Assert.IsNotNull(await authScope.ServiceProvider.GetRequiredService<ISoftwareClientAuthenticator>()
                .AuthenticateAsync(minted.Token));
        }

        // A new environment brings its pending token along; deleting the environment removes it again.
        await secrets.AddEnvironmentAsync(tenantId, appId, "Staging", admin);
        var staging = (await secrets.ListEnvironmentsAsync(tenantId, appId)).Single(e => e.Name == "Staging");
        var stagingToken = (await tokens.ListAsync(tenantId, appId)).Single(t => t.EnvironmentId == staging.Id);
        Assert.AreEqual("bird-staging", stagingToken.Name);
        Assert.IsFalse(stagingToken.HasSecret);

        await secrets.DeleteEnvironmentAsync(tenantId, appId, staging.Id, admin);
        Assert.IsFalse((await tokens.ListAsync(tenantId, appId)).Any(t => t.Id == stagingToken.Id));
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Custom_default_environments_drive_new_applications()
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

        using var scope = ScopeFor(provider, admin, tenantId);
        var defaults = scope.ServiceProvider.GetRequiredService<IDefaultEnvironmentService>();
        var projects = scope.ServiceProvider.GetRequiredService<IProjectService>();
        var secrets = scope.ServiceProvider.GetRequiredService<ISoftwareSecretService>();

        // No rows → the built-in set applies to a new application.
        Assert.AreEqual(0, (await defaults.ListAsync(tenantId)).Count);
        var builtinApp = await projects.CreateAsync(tenantId, "builtin", admin);
        Assert.AreEqual(
            EnvironmentName.DefaultSet.Count(),
            (await secrets.ListEnvironmentsAsync(tenantId, builtinApp)).Count);

        // Customize copies the built-in set into editable rows; then trim it down to Test + Production.
        await defaults.CustomizeAsync(tenantId, admin);
        var rows = await defaults.ListAsync(tenantId);
        Assert.AreEqual(EnvironmentName.DefaultSet.Count(), rows.Count);
        foreach (var row in rows.Where(r => r.Name is not ("Test" or "Production")))
        {
            await defaults.DeleteAsync(tenantId, row.Id, admin);
        }
        await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => defaults.AddAsync(tenantId, "Test", admin));

        // A new application now starts with exactly the customized set.
        var customApp = await projects.CreateAsync(tenantId, "custom", admin);
        CollectionAssert.AreEquivalent(
            new[] { "Test", "Production" },
            (await secrets.ListEnvironmentsAsync(tenantId, customApp)).Select(e => e.Name).ToArray());

        // Deleting the remaining rows returns to the built-in set; plain members may not mutate.
        foreach (var row in await defaults.ListAsync(tenantId))
        {
            await defaults.DeleteAsync(tenantId, row.Id, admin);
        }
        var backToBuiltin = await projects.CreateAsync(tenantId, "again", admin);
        Assert.AreEqual(
            EnvironmentName.DefaultSet.Count(),
            (await secrets.ListEnvironmentsAsync(tenantId, backToBuiltin)).Count);

        using var memberScope = ScopeFor(provider, member, tenantId);
        var memberDefaults = memberScope.ServiceProvider.GetRequiredService<IDefaultEnvironmentService>();
        await Assert.ThrowsExactlyAsync<UnauthorizedAccessException>(() => memberDefaults.CustomizeAsync(tenantId, member));
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Delete_cascades_environments_secrets_and_tokens()
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

        Guid appId;
        string plaintextToken;
        using (var scope = ScopeFor(provider, admin, tenantId))
        {
            var projects = scope.ServiceProvider.GetRequiredService<IProjectService>();
            appId = await projects.CreateAsync(tenantId, "doomed", admin);

            var secrets = scope.ServiceProvider.GetRequiredService<ISoftwareSecretService>();
            await secrets.StoreAsync(new StoreSoftwareSecretCommand(tenantId, appId, "Production", "Api:Key", "v1", admin));

            var tokens = scope.ServiceProvider.GetRequiredService<ISoftwareClientTokenService>();
            var issued = await tokens.IssueAsync(new IssueSoftwareClientTokenCommand(tenantId, appId, "Production", "doomed-production-", null, admin));
            plaintextToken = issued.Token;

            await projects.DeleteAsync(tenantId, appId, admin);
            Assert.IsFalse((await projects.ListAsync(tenantId)).Any(p => p.Id == appId));
        }

        // Everything scoped to the application is gone, and its token is rejected at the door.
        using (var scope = ScopeFor(provider, admin, tenantId))
        {
            var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
            Assert.IsFalse(await db.RuntimeEnvironments.AnyAsync(e => e.ProjectId == appId));
            Assert.IsFalse(await db.SoftwareSecrets.AnyAsync(s => s.ProjectId == appId));
            Assert.IsFalse(await db.SoftwareClientTokens.AnyAsync(t => t.ProjectId == appId));
        }

        using (var scope = provider.CreateScope())
        {
            Assert.IsNull(await scope.ServiceProvider.GetRequiredService<ISoftwareClientAuthenticator>()
                .AuthenticateAsync(plaintextToken));
        }
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

    private static IServiceScope ScopeFor(ServiceProvider provider, Guid userId, Guid tenantId)
    {
        var scope = provider.CreateScope();
        scope.ServiceProvider.GetRequiredService<ITenantScopeSetter>().SetTenant(tenantId);
        scope.ServiceProvider.GetRequiredService<IUserScopeSetter>().SetUser(userId);
        return scope;
    }

    private static async Task SeedTenantAsync(ServiceProvider provider, Guid tenantId, params (Guid UserId, TenantRole Role)[] users)
    {
        using var scope = provider.CreateScope();
        scope.ServiceProvider.GetRequiredService<ITenantScopeSetter>().SetTenant(tenantId);
        var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
        db.Tenants.Add(new Tenant(tenantId, "apps-test", isSystemTenant: false, DateTimeOffset.UtcNow));
        foreach (var (userId, role) in users)
        {
            db.Users.Add(new AppUser(userId, issuer: null, externalId: userId.ToString(), displayName: $"user-{userId:N}", isSystemAdmin: false, DateTimeOffset.UtcNow));
            db.TenantMemberships.Add(new TenantMembership(Guid.NewGuid(), tenantId, userId, role, DateTimeOffset.UtcNow));
        }

        await db.SaveChangesAsync();
    }
}
