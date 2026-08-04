using System.Security.Cryptography;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Identity;
using Am.Keyward.Core.Domain.ValueObjects;
using Am.Keyward.Infrastructure;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.Extensions.DependencyInjection;

namespace Am.Keyward.Tests;

/// <summary>
/// The bulk import of applications + secret keys: the parser (indented text, JSON application map,
/// appsettings.json flattening — pure unit tests) and the import service against a real SQL Server
/// (additive/idempotent semantics, keys created without values, operator gating). Integration tests
/// skip (inconclusive) when no DB is reachable.
/// </summary>
[TestClass]
public class ApplicationImportTests
{
    private static readonly string ConnectionString = TestConfig.ConnectionString;

    // --- parser: indented text ---

    [TestMethod, TestCategory("Unit")]
    public void Text_format_parses_applications_keys_comments_and_duplicates()
    {
        var plan = ApplicationImportParser.Parse("""
            # comment
            Shop.Web
                ConnectionStrings:Main
                Smtp:Host

                connectionstrings:main
            Shop.Worker
                ApiKeys:OpenAi
            SHOP.WEB
                Smtp:Port
            """);

        Assert.IsTrue(plan.IsValid);
        Assert.AreEqual(2, plan.Applications.Count);
        // Duplicate keys (case-insensitive) are de-duplicated; a re-listed application merges.
        CollectionAssert.AreEqual(
            new[] { "ConnectionStrings:Main", "Smtp:Host", "Smtp:Port" },
            plan.Applications[0].Keys.ToArray());
        Assert.AreEqual("Shop.Web", plan.Applications[0].Name);
        CollectionAssert.AreEqual(new[] { "ApiKeys:OpenAi" }, plan.Applications[1].Keys.ToArray());
    }

    [TestMethod, TestCategory("Unit")]
    public void Text_format_reports_orphan_keys_and_invalid_keys_with_line_numbers()
    {
        var plan = ApplicationImportParser.Parse("    Orphan:Key\nApp\n    inva lid\n    Good:Key");

        Assert.IsFalse(plan.IsValid);
        Assert.AreEqual(2, plan.Errors.Count);
        Assert.AreEqual(1, plan.Errors[0].Line); // key before any application
        Assert.AreEqual(3, plan.Errors[1].Line); // space is not a valid key character
        // The valid part still parses, so the UI can show both errors and what WOULD import.
        CollectionAssert.AreEqual(new[] { "Good:Key" }, plan.Applications.Single().Keys.ToArray());
    }

    [TestMethod, TestCategory("Unit")]
    public void Empty_input_is_an_error()
    {
        Assert.IsFalse(ApplicationImportParser.Parse("   ").IsValid);
        Assert.IsFalse(ApplicationImportParser.Parse(null).IsValid);
        Assert.IsFalse(ApplicationImportParser.Parse("# only a comment").IsValid);
    }

    // --- parser: JSON application map ---

    [TestMethod, TestCategory("Unit")]
    public void Json_application_map_parses()
    {
        var plan = ApplicationImportParser.Parse("""{ "Shop.Web": ["ConnectionStrings:Main", "Smtp:Host"], "Shop.Worker": [] }""");

        Assert.IsTrue(plan.IsValid);
        Assert.AreEqual(2, plan.Applications.Count);
        CollectionAssert.AreEqual(new[] { "ConnectionStrings:Main", "Smtp:Host" }, plan.Applications[0].Keys.ToArray());
        Assert.AreEqual(0, plan.Applications[1].Keys.Count);
    }

    [TestMethod, TestCategory("Unit")]
    public void Json_application_map_rejects_non_string_keys()
    {
        var plan = ApplicationImportParser.Parse("""{ "Shop.Web": ["Good:Key", 42] }""");

        Assert.IsFalse(plan.IsValid);
        CollectionAssert.AreEqual(new[] { "Good:Key" }, plan.Applications.Single().Keys.ToArray());
    }

    [TestMethod, TestCategory("Unit")]
    public void Invalid_json_is_an_error_with_line_number()
    {
        var plan = ApplicationImportParser.Parse("{\n  \"Shop.Web\": [broken\n}");

        Assert.IsFalse(plan.IsValid);
        Assert.IsTrue(plan.Errors.Single().Line > 0);
        Assert.IsTrue(plan.Errors.Single().Message.StartsWith("Invalid JSON"));
    }

    // --- parser: appsettings.json flattening ---

    [TestMethod, TestCategory("Unit")]
    public void Appsettings_json_flattens_leaf_paths_and_ignores_values()
    {
        var plan = ApplicationImportParser.Parse("""
            {
              // comments and trailing commas are tolerated
              "ConnectionStrings": { "Main": "Server=...;Password=hunter2" },
              "Smtp": { "Host": "smtp.example.com", "Port": 587 },
              "AllowedHosts": "*",
              "Endpoints": [ "https://a", "https://b" ],
            }
            """, fallbackApplicationName: "Shop.Web");

        // "*" is not a valid key character -> AllowedHosts's VALUE never matters, but its PATH is the key.
        Assert.IsTrue(plan.IsValid);
        var application = plan.Applications.Single();
        Assert.AreEqual("Shop.Web", application.Name);
        CollectionAssert.AreEqual(
            new[] { "ConnectionStrings:Main", "Smtp:Host", "Smtp:Port", "AllowedHosts", "Endpoints:0", "Endpoints:1" },
            application.Keys.ToArray());
    }

    [TestMethod, TestCategory("Unit")]
    public void Appsettings_json_without_target_application_name_is_an_error()
    {
        var plan = ApplicationImportParser.Parse("""{ "Smtp": { "Host": "x" } }""");

        Assert.IsFalse(plan.IsValid);
        StringAssert.Contains(plan.Errors.Single().Message, "appsettings");
    }

    // --- import service (SQL Server) ---

    [TestMethod, TestCategory("Integration")]
    public async Task Import_is_additive_idempotent_and_creates_keys_without_values()
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
        var import = scope.ServiceProvider.GetRequiredService<IApplicationImportService>();

        // An existing application with one valued key — the import must reuse it and never touch the value.
        var existingApp = await projects.CreateAsync(tenantId, "existing", admin);
        await secrets.StoreAsync(new StoreSoftwareSecretCommand(tenantId, existingApp, "Production", "Api:Key", "v1", admin));

        var plan = ApplicationImportParser.Parse("""
            EXISTING
                Api:Key
                Smtp:Host
            fresh
                ConnectionStrings:Main
            """);
        Assert.IsTrue(plan.IsValid);

        // Preview flags what exists (application match and key match are case-insensitive).
        var preview = await import.PreviewAsync(tenantId, plan);
        Assert.IsTrue(preview.Applications.Single(a => a.Name == "EXISTING").Exists);
        Assert.IsFalse(preview.Applications.Single(a => a.Name == "fresh").Exists);
        Assert.IsTrue(preview.Applications.Single(a => a.Name == "EXISTING").Keys.Single(k => k.Key == "Api:Key").Exists);
        Assert.AreEqual(1, preview.NewApplications);
        Assert.AreEqual(2, preview.NewKeys);
        Assert.AreEqual(1, preview.SkippedKeys);

        var result = await import.ImportAsync(tenantId, plan, admin);
        Assert.AreEqual(1, result.ApplicationsCreated);
        Assert.AreEqual(2, result.SecretsCreated);
        Assert.AreEqual(1, result.SecretsSkipped);

        // The new application got the default environment set; its imported key has no value anywhere.
        var freshApp = (await projects.ListAsync(tenantId)).Single(p => p.Name == "fresh");
        Assert.AreEqual(EnvironmentName.DefaultSet.Count, freshApp.EnvironmentCount);
        var freshKey = (await secrets.ListSecretsAsync(tenantId, freshApp.Id)).Single();
        Assert.AreEqual("ConnectionStrings:Main", freshKey.Key);
        Assert.AreEqual(0, freshKey.EnvironmentsWithValue.Count);

        // The pre-existing value survived the import untouched.
        Assert.AreEqual("v1", await secrets.ReadAsync(new ReadSoftwareSecretQuery(tenantId, existingApp, "Production", "Api:Key", admin)));

        // Re-importing the same plan is a no-op (additive + idempotent).
        var again = await import.ImportAsync(tenantId, plan, admin);
        Assert.AreEqual(0, again.ApplicationsCreated);
        Assert.AreEqual(0, again.SecretsCreated);
        Assert.AreEqual(3, again.SecretsSkipped);

        // A plain member may not import; an invalid plan is refused outright.
        using var memberScope = ScopeFor(provider, member, tenantId);
        var memberImport = memberScope.ServiceProvider.GetRequiredService<IApplicationImportService>();
        await Assert.ThrowsExactlyAsync<UnauthorizedAccessException>(() => memberImport.ImportAsync(tenantId, plan, member));
        await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            () => import.ImportAsync(tenantId, ApplicationImportParser.Parse(""), admin));
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
        db.Tenants.Add(new Tenant(tenantId, "import-test", isSystemTenant: false, DateTimeOffset.UtcNow));
        foreach (var (userId, role) in users)
        {
            db.Users.Add(new AppUser(userId, issuer: null, externalId: userId.ToString(), displayName: $"user-{userId:N}", isSystemAdmin: false, DateTimeOffset.UtcNow));
            db.TenantMemberships.Add(new TenantMembership(Guid.NewGuid(), tenantId, userId, role, DateTimeOffset.UtcNow));
        }

        await db.SaveChangesAsync();
    }
}
