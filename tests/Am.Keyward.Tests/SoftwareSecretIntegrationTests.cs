using System.Security.Cryptography;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Identity;
using Am.Keyward.Core.Domain.Software;
using Am.Keyward.Core.Domain.ValueObjects;
using Am.Keyward.Infrastructure;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Am.Keyward.Tests;

/// <summary>
/// Walking-skeleton end-to-end test: DI → real SQL Server → encrypt + store → read + decrypt. Skips
/// (inconclusive) when no SQL Server is reachable, so CI without a database stays green.
/// </summary>
[TestClass]
public class SoftwareSecretIntegrationTests
{
    private static readonly string ConnectionString = TestConfig.ConnectionString;

    /// <summary>Opens a DI scope with the server-authoritative tenant scope established (as a host edge would).</summary>
    private static IServiceScope ScopeFor(ServiceProvider provider, Guid tenantId)
    {
        var scope = provider.CreateScope();
        scope.ServiceProvider.GetRequiredService<ITenantScopeSetter>().SetTenant(tenantId);
        return scope;
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Store_then_read_roundtrips_and_is_encrypted_at_rest()
    {
        var services = new ServiceCollection();
        services.AddKeyward(ConnectionString, RandomNumberGenerator.GetBytes(32), "test-kek:v1");
        await using var provider = services.BuildServiceProvider();

        var tenantId = Guid.NewGuid();
        var projectId = Guid.NewGuid();
        const string plaintext = "Server=db;User Id=app;Password=hunter2";

        // Arrange: ensure DB reachable, then seed tenant + project + Production environment.
        using (var scope = ScopeFor(provider, tenantId))
        {
            var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
            if (!await db.Database.CanConnectAsync())
            {
                Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
                return;
            }

            db.Tenants.Add(new Tenant(tenantId, "system", isSystemTenant: true, DateTimeOffset.UtcNow));
            var project = new Project(projectId, tenantId, OwnerType.Tenant, tenantId, "walking-skeleton", DateTimeOffset.UtcNow);
            project.AddEnvironment(Guid.NewGuid(), EnvironmentName.Production, DateTimeOffset.UtcNow);
            db.Projects.Add(project);
            await db.SaveChangesAsync();
        }

        // Act: store, then read (separate scopes = separate DbContext instances).
        using (var scope = ScopeFor(provider, tenantId))
        {
            await scope.ServiceProvider.GetRequiredService<ISoftwareSecretService>()
                .StoreAsync(new StoreSoftwareSecretCommand(tenantId, projectId, "Production", "ConnectionStrings:Main", plaintext, ActorUserId: null));
        }

        string? readBack;
        using (var scope = ScopeFor(provider, tenantId))
        {
            readBack = await scope.ServiceProvider.GetRequiredService<ISoftwareSecretService>()
                .ReadAsync(new ReadSoftwareSecretQuery(tenantId, projectId, "Production", "ConnectionStrings:Main", ActorUserId: null));
        }

        // Assert: round-trip recovered the value.
        Assert.AreEqual(plaintext, readBack);

        // Assert: the value is encrypted at rest (the stored column never contains the plaintext),
        // and a tamper-evident audit entry exists for this tenant.
        using (var scope = ScopeFor(provider, tenantId))
        {
            var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();

            var storedColumns = await db.Database
                .SqlQueryRaw<string>("SELECT [Encrypted] AS [Value] FROM [amkeyward].[SecretVersions]")
                .ToListAsync();
            Assert.IsNotEmpty(storedColumns);
            Assert.IsFalse(storedColumns.Any(c => c.Contains("hunter2", StringComparison.Ordinal)),
                "Plaintext must never be stored at rest.");

            var auditCount = await db.AuditEntries.CountAsync(a => a.TenantId == tenantId);
            Assert.IsGreaterThanOrEqualTo(2, auditCount, "Store and read should both be audited.");
        }
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Store_two_environments_for_same_key_keeps_them_independent()
    {
        var services = new ServiceCollection();
        services.AddKeyward(ConnectionString, RandomNumberGenerator.GetBytes(32), "test-kek:v1");
        await using var provider = services.BuildServiceProvider();

        var tenantId = Guid.NewGuid();
        var projectId = Guid.NewGuid();

        using (var scope = ScopeFor(provider, tenantId))
        {
            var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
            if (!await db.Database.CanConnectAsync())
            {
                Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
                return;
            }

            db.Tenants.Add(new Tenant(tenantId, "system", isSystemTenant: true, DateTimeOffset.UtcNow));
            var project = new Project(projectId, tenantId, OwnerType.Tenant, tenantId, "multi-env", DateTimeOffset.UtcNow);
            project.AddEnvironment(Guid.NewGuid(), EnvironmentName.Production, DateTimeOffset.UtcNow);
            project.AddEnvironment(Guid.NewGuid(), EnvironmentName.Development, DateTimeOffset.UtcNow);
            db.Projects.Add(project);
            await db.SaveChangesAsync();
        }

        // Both stores share one DbContext (mirrors the Blazor circuit-scoped context that triggered the bug).
        using (var scope = ScopeFor(provider, tenantId))
        {
            var svc = scope.ServiceProvider.GetRequiredService<ISoftwareSecretService>();
            await svc.StoreAsync(new StoreSoftwareSecretCommand(tenantId, projectId, "Production", "ConnectionStrings:Main", "prod-value", null));
            await svc.StoreAsync(new StoreSoftwareSecretCommand(tenantId, projectId, "Development", "ConnectionStrings:Main", "dev-value", null));
        }

        using (var scope = ScopeFor(provider, tenantId))
        {
            var svc = scope.ServiceProvider.GetRequiredService<ISoftwareSecretService>();
            Assert.AreEqual("prod-value", await svc.ReadAsync(new ReadSoftwareSecretQuery(tenantId, projectId, "Production", "ConnectionStrings:Main", null)));
            Assert.AreEqual("dev-value", await svc.ReadAsync(new ReadSoftwareSecretQuery(tenantId, projectId, "Development", "ConnectionStrings:Main", null)));
        }
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Rotation_metadata_survives_a_value_being_set_and_never_blocks_a_read()
    {
        var services = new ServiceCollection();
        services.AddKeyward(ConnectionString, RandomNumberGenerator.GetBytes(32), "test-kek:v1");
        await using var provider = services.BuildServiceProvider();

        var tenantId = Guid.NewGuid();
        var projectId = Guid.NewGuid();

        using (var scope = ScopeFor(provider, tenantId))
        {
            var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
            if (!await db.Database.CanConnectAsync())
            {
                Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
                return;
            }

            db.Tenants.Add(new Tenant(tenantId, "system", isSystemTenant: true, DateTimeOffset.UtcNow));
            var project = new Project(projectId, tenantId, OwnerType.Tenant, tenantId, "rotation", DateTimeOffset.UtcNow);
            project.AddEnvironment(Guid.NewGuid(), EnvironmentName.Production, DateTimeOffset.UtcNow);
            db.Projects.Add(project);
            await db.SaveChangesAsync();
        }

        // A key with NO value anywhere: the date and note must still attach (that is the point of them).
        using (var scope = ScopeFor(provider, tenantId))
        {
            var svc = scope.ServiceProvider.GetRequiredService<ISoftwareSecretService>();
            Assert.IsTrue(await svc.CreateSecretAsync(tenantId, projectId, "AiEngine:ApiKey", null));
            await svc.SetValueRotationAsync(
                tenantId, projectId, "AiEngine:ApiKey", "Production",
                DateTimeOffset.UtcNow.AddDays(-1), "Console, API keys, create new", null);
        }

        using (var scope = ScopeFor(provider, tenantId))
        {
            var svc = scope.ServiceProvider.GetRequiredService<ISoftwareSecretService>();
            var detail = await svc.GetSecretAsync(tenantId, projectId, "AiEngine:ApiKey");
            var production = detail!.Environments.Single(e => e.Environment == "Production");
            Assert.IsFalse(production.HasValue, "rotation metadata must not fabricate a value");
            Assert.IsNotNull(production.ExpiresAt);
            Assert.AreEqual("Console, API keys, create new", production.Note);

            // Now store a value — with an ALREADY EXPIRED date — and read it back: expiry is advisory, so a
            // deployed application keeps working past the date.
            await svc.StoreAsync(new StoreSoftwareSecretCommand(tenantId, projectId, "Production", "AiEngine:ApiKey", "sk-live", null));
        }

        using (var scope = ScopeFor(provider, tenantId))
        {
            var svc = scope.ServiceProvider.GetRequiredService<ISoftwareSecretService>();
            Assert.AreEqual("sk-live", await svc.ReadAsync(new ReadSoftwareSecretQuery(tenantId, projectId, "Production", "AiEngine:ApiKey", null)));

            var detail = await svc.GetSecretAsync(tenantId, projectId, "AiEngine:ApiKey");
            var production = detail!.Environments.Single(e => e.Environment == "Production");
            Assert.IsTrue(production.HasValue);
            Assert.AreEqual("Console, API keys, create new", production.Note, "storing a value keeps the rotation metadata");

            // Clearing works through the same call.
            await svc.SetValueRotationAsync(tenantId, projectId, "AiEngine:ApiKey", "Production", null, null, null);
            var cleared = (await svc.GetSecretAsync(tenantId, projectId, "AiEngine:ApiKey"))!
                .Environments.Single(e => e.Environment == "Production");
            Assert.IsNull(cleared.ExpiresAt);
            Assert.AreEqual("", cleared.Note);
        }
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Rename_keeps_every_environment_value_readable_under_the_new_key()
    {
        var services = new ServiceCollection();
        services.AddKeyward(ConnectionString, RandomNumberGenerator.GetBytes(32), "test-kek:v1");
        await using var provider = services.BuildServiceProvider();

        var tenantId = Guid.NewGuid();
        var projectId = Guid.NewGuid();

        using (var scope = ScopeFor(provider, tenantId))
        {
            var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
            if (!await db.Database.CanConnectAsync())
            {
                Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
                return;
            }

            db.Tenants.Add(new Tenant(tenantId, "system", isSystemTenant: true, DateTimeOffset.UtcNow));
            var project = new Project(projectId, tenantId, OwnerType.Tenant, tenantId, "rename-key", DateTimeOffset.UtcNow);
            project.AddEnvironment(Guid.NewGuid(), EnvironmentName.Production, DateTimeOffset.UtcNow);
            project.AddEnvironment(Guid.NewGuid(), EnvironmentName.Development, DateTimeOffset.UtcNow);
            db.Projects.Add(project);
            await db.SaveChangesAsync();
        }

        using (var scope = ScopeFor(provider, tenantId))
        {
            var svc = scope.ServiceProvider.GetRequiredService<ISoftwareSecretService>();
            await svc.StoreAsync(new StoreSoftwareSecretCommand(tenantId, projectId, "Production", "orderdesk-apikey-51833", "prod-value", null));
            await svc.StoreAsync(new StoreSoftwareSecretCommand(tenantId, projectId, "Development", "orderdesk-apikey-51833", "dev-value", null));
        }

        using (var scope = ScopeFor(provider, tenantId))
        {
            await scope.ServiceProvider.GetRequiredService<ISoftwareSecretService>()
                .RenameSecretAsync(tenantId, projectId, "orderdesk-apikey-51833", "orderdesk-apikey-51833-balleristo", null);
        }

        // The values are bound to the secret's ID, not its key — so every environment still decrypts,
        // and the old key is gone.
        using (var scope = ScopeFor(provider, tenantId))
        {
            var svc = scope.ServiceProvider.GetRequiredService<ISoftwareSecretService>();
            Assert.AreEqual("prod-value", await svc.ReadAsync(new ReadSoftwareSecretQuery(tenantId, projectId, "Production", "orderdesk-apikey-51833-balleristo", null)));
            Assert.AreEqual("dev-value", await svc.ReadAsync(new ReadSoftwareSecretQuery(tenantId, projectId, "Development", "orderdesk-apikey-51833-balleristo", null)));
            Assert.IsNull(await svc.ReadAsync(new ReadSoftwareSecretQuery(tenantId, projectId, "Production", "orderdesk-apikey-51833", null)));

            var keys = await svc.ListSecretsAsync(tenantId, projectId);
            Assert.AreEqual(1, keys.Count);
            Assert.AreEqual("orderdesk-apikey-51833-balleristo", keys[0].Key);
        }
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Rename_onto_an_existing_key_is_rejected()
    {
        var services = new ServiceCollection();
        services.AddKeyward(ConnectionString, RandomNumberGenerator.GetBytes(32), "test-kek:v1");
        await using var provider = services.BuildServiceProvider();

        var tenantId = Guid.NewGuid();
        var projectId = Guid.NewGuid();

        using (var scope = ScopeFor(provider, tenantId))
        {
            var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
            if (!await db.Database.CanConnectAsync())
            {
                Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
                return;
            }

            db.Tenants.Add(new Tenant(tenantId, "system", isSystemTenant: true, DateTimeOffset.UtcNow));
            var project = new Project(projectId, tenantId, OwnerType.Tenant, tenantId, "rename-conflict", DateTimeOffset.UtcNow);
            project.AddEnvironment(Guid.NewGuid(), EnvironmentName.Production, DateTimeOffset.UtcNow);
            db.Projects.Add(project);
            await db.SaveChangesAsync();
        }

        using (var scope = ScopeFor(provider, tenantId))
        {
            var svc = scope.ServiceProvider.GetRequiredService<ISoftwareSecretService>();
            await svc.StoreAsync(new StoreSoftwareSecretCommand(tenantId, projectId, "Production", "Api:First", "a", null));
            await svc.StoreAsync(new StoreSoftwareSecretCommand(tenantId, projectId, "Production", "Api:Second", "b", null));
        }

        using (var scope = ScopeFor(provider, tenantId))
        {
            var svc = scope.ServiceProvider.GetRequiredService<ISoftwareSecretService>();
            // Case-insensitive, like the "key already exists" check on creation.
            await Assert.ThrowsExactlyAsync<InvalidOperationException>(
                () => svc.RenameSecretAsync(tenantId, projectId, "Api:First", "api:second", null));
        }
    }
}
