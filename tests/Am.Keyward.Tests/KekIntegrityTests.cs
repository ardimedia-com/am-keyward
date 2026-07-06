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
/// Backup/restore consistency: the KEK integrity job confirms every stored envelope resolves under an
/// available KEK id, and flags the slots that don't (a DB restored without its matching KEK store). Runs
/// against a real SQL Server; skips when none is reachable.
/// </summary>
[TestClass]
public class KekIntegrityTests
{
    private static readonly string ConnectionString = TestConfig.ConnectionString;

    [TestMethod, TestCategory("Integration")]
    public async Task Consistent_when_kek_resolves_and_flags_an_unresolvable_kek()
    {
        var tenantId = Guid.NewGuid();
        var projectId = Guid.NewGuid();

        // Store one secret under KEK "test-kek:v1".
        var withV1 = new ServiceCollection();
        withV1.AddKeyward(ConnectionString, RandomNumberGenerator.GetBytes(32), "test-kek:v1");
        await using var providerV1 = withV1.BuildServiceProvider();

        using (var scope = ScopeFor(providerV1, tenantId))
        {
            var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
            if (!await db.Database.CanConnectAsync())
            {
                Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
                return;
            }

            db.Tenants.Add(new Tenant(tenantId, "system", isSystemTenant: true, DateTimeOffset.UtcNow));
            var project = new Project(projectId, tenantId, OwnerType.Tenant, tenantId, "kek-integrity", DateTimeOffset.UtcNow);
            project.AddEnvironment(Guid.NewGuid(), EnvironmentName.Production, DateTimeOffset.UtcNow);
            db.Projects.Add(project);
            await db.SaveChangesAsync();
        }

        using (var scope = ScopeFor(providerV1, tenantId))
        {
            await scope.ServiceProvider.GetRequiredService<ISoftwareSecretService>()
                .StoreAsync(new StoreSoftwareSecretCommand(tenantId, projectId, "Production", "ConnectionStrings:Main", "value", null));
        }

        // The current KEK resolves the stored envelope → consistent (no issues for this row).
        using (var scope = ScopeFor(providerV1, tenantId))
        {
            var report = await scope.ServiceProvider.GetRequiredService<IKekIntegrityVerifier>().VerifyAsync();
            Assert.IsGreaterThanOrEqualTo(1, report.Checked);
            Assert.IsFalse(report.Unresolvable.Any(i => i.ResourceType == "SecretVersion" && i.KekId == "test-kek:v1"),
                "A row wrapped under the current KEK must resolve.");
        }

        // Simulate a DB restored without its KEK store: a provider that only knows a different KEK version.
        var withV2 = new ServiceCollection();
        withV2.AddKeyward(ConnectionString, RandomNumberGenerator.GetBytes(32), "test-kek:v2");
        await using var providerV2 = withV2.BuildServiceProvider();

        using (var scope = ScopeFor(providerV2, tenantId))
        {
            var report = await scope.ServiceProvider.GetRequiredService<IKekIntegrityVerifier>().VerifyAsync();
            Assert.IsFalse(report.IsConsistent, "An envelope under an unavailable KEK must be flagged.");
            Assert.IsTrue(report.Unresolvable.Any(i => i.KekId == "test-kek:v1"),
                "The unresolvable KEK id should be reported.");
        }
    }

    private static IServiceScope ScopeFor(ServiceProvider provider, Guid tenantId)
    {
        var scope = provider.CreateScope();
        scope.ServiceProvider.GetRequiredService<ITenantScopeSetter>().SetTenant(tenantId);
        return scope;
    }
}
