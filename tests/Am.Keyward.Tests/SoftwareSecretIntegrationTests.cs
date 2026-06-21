using System.Security.Cryptography;
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
    private const string ConnectionString = "Server=localhost;Database=amkeyward;Integrated Security=True;Encrypt=False";

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
        using (var scope = provider.CreateScope())
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
        using (var scope = provider.CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<ISoftwareSecretService>()
                .StoreAsync(new StoreSoftwareSecretCommand(tenantId, projectId, "Production", "ConnectionStrings:Main", plaintext, ActorUserId: null));
        }

        string? readBack;
        using (var scope = provider.CreateScope())
        {
            readBack = await scope.ServiceProvider.GetRequiredService<ISoftwareSecretService>()
                .ReadAsync(new ReadSoftwareSecretQuery(tenantId, projectId, "Production", "ConnectionStrings:Main", ActorUserId: null));
        }

        // Assert: round-trip recovered the value.
        Assert.AreEqual(plaintext, readBack);

        // Assert: the value is encrypted at rest (the stored column never contains the plaintext),
        // and a tamper-evident audit entry exists for this tenant.
        using (var scope = provider.CreateScope())
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

        using (var scope = provider.CreateScope())
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
        using (var scope = provider.CreateScope())
        {
            var svc = scope.ServiceProvider.GetRequiredService<ISoftwareSecretService>();
            await svc.StoreAsync(new StoreSoftwareSecretCommand(tenantId, projectId, "Production", "ConnectionStrings:Main", "prod-value", null));
            await svc.StoreAsync(new StoreSoftwareSecretCommand(tenantId, projectId, "Development", "ConnectionStrings:Main", "dev-value", null));
        }

        using (var scope = provider.CreateScope())
        {
            var svc = scope.ServiceProvider.GetRequiredService<ISoftwareSecretService>();
            Assert.AreEqual("prod-value", await svc.ReadAsync(new ReadSoftwareSecretQuery(tenantId, projectId, "Production", "ConnectionStrings:Main", null)));
            Assert.AreEqual("dev-value", await svc.ReadAsync(new ReadSoftwareSecretQuery(tenantId, projectId, "Development", "ConnectionStrings:Main", null)));
        }
    }
}
