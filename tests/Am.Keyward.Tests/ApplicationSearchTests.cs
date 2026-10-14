using System.Security.Cryptography;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Identity;
using Am.Keyward.Infrastructure;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.Extensions.DependencyInjection;

namespace Am.Keyward.Tests;

/// <summary>
/// The search across all applications (IProjectService.SearchAsync) against a real SQL Server: what it finds for a
/// software operator (names, environments, keys, rotation notes, app tokens), what a plain member sees (names and
/// environments only), and that values are never searched.
/// </summary>
[TestClass]
public class ApplicationSearchTests
{
    private static readonly string ConnectionString = TestConfig.ConnectionString;

    [TestMethod, TestCategory("Integration")]
    public async Task Search_finds_names_keys_notes_and_tokens_but_never_values()
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
        var secrets = scope.ServiceProvider.GetRequiredService<ISoftwareSecretService>();
        var tokens = scope.ServiceProvider.GetRequiredService<ISoftwareClientTokenService>();

        var shop = await projects.CreateAsync(tenantId, "Shop.Web", admin);
        await projects.CreateAsync(tenantId, "Other.Worker", admin);
        await secrets.StoreAsync(new StoreSoftwareSecretCommand(tenantId, shop, "Production", "Smtp:Host", "value-findme", admin));
        await secrets.SetValueRotationAsync(tenantId, shop, "Smtp:Host", "Production", null, "renew at portal-xyz", admin);
        var issued = await tokens.IssueAsync(new IssueSoftwareClientTokenCommand(tenantId, shop, "Production", "shop-prod", null, admin, Note: "runs on srv-abc"));

        var key = await projects.SearchAsync(tenantId, admin, "smtp");
        Assert.AreEqual(ApplicationSearchField.Key, key.Single().Field);
        Assert.AreEqual("Smtp:Host", key.Single().Detail);
        Assert.AreEqual(shop, key.Single().ApplicationId);

        var note = (await projects.SearchAsync(tenantId, admin, "PORTAL-XYZ")).Single();
        Assert.AreEqual(ApplicationSearchField.RotationNote, note.Field);
        Assert.AreEqual(("Smtp:Host", "Production"), (note.Detail, note.Environment));

        var token = (await projects.SearchAsync(tenantId, admin, "srv-abc")).Single();
        Assert.AreEqual(ApplicationSearchField.Token, token.Field);
        Assert.AreEqual(issued.TokenId, token.TokenId);

        // Every application starts with the default environments: «prod» finds Production in both and the token.
        var prod = await projects.SearchAsync(tenantId, admin, "prod");
        Assert.AreEqual(2, prod.Count(h => h.Field == ApplicationSearchField.Environment));
        Assert.IsTrue(prod.Any(h => h.Field == ApplicationSearchField.Token));

        Assert.AreEqual(0, (await projects.SearchAsync(tenantId, admin, "findme")).Count, "values are never searched");
        Assert.AreEqual(0, (await projects.SearchAsync(tenantId, admin, "s")).Count, "one character is no search");

        // A member without the software role sees the list (names and environments), not the manage tabs.
        using var memberScope = ScopeFor(provider, member, tenantId);
        var memberProjects = memberScope.ServiceProvider.GetRequiredService<IProjectService>();
        Assert.AreEqual(0, (await memberProjects.SearchAsync(tenantId, member, "smtp")).Count);
        Assert.AreEqual(0, (await memberProjects.SearchAsync(tenantId, member, "srv-abc")).Count);
        Assert.AreEqual(ApplicationSearchField.Application, (await memberProjects.SearchAsync(tenantId, member, "shop.web")).Single().Field);
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
        db.Tenants.Add(new Tenant(tenantId, "search-test", isSystemTenant: false, DateTimeOffset.UtcNow));
        foreach (var (userId, role) in users)
        {
            db.Users.Add(new AppUser(userId, issuer: null, externalId: userId.ToString(), displayName: $"user-{userId:N}", isSystemAdmin: false, DateTimeOffset.UtcNow));
            db.TenantMemberships.Add(new TenantMembership(Guid.NewGuid(), tenantId, userId, role, DateTimeOffset.UtcNow));
        }

        await db.SaveChangesAsync();
    }
}
