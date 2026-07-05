using System.Security.Cryptography;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Identity;
using Am.Keyward.Core.Domain.Software;
using Am.Keyward.Core.Domain.ValueObjects;
using Am.Keyward.Infrastructure;
using Am.Keyward.Infrastructure.Persistence;
using Am.Keyward.Infrastructure.Tenancy;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Am.Keyward.Tests;

/// <summary>
/// Regression tests for the row-level-security "system read" bypass that lets trusted server-side maintenance
/// read across tenant/owner scope: the audit-chain writer (C1) and the KEK-integrity / ops-monitor sweep (H1).
/// Runs against a real SQL Server; skips when none is reachable.
/// </summary>
[TestClass]
public class AuditAndMonitoringRlsTests
{
    private const string ConnectionString = "Server=localhost;Database=amkeyward;Integrated Security=True;Encrypt=False";

    [TestMethod, TestCategory("Integration")]
    public async Task Personal_vault_audit_chain_does_not_fork_while_a_tenant_is_in_scope()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var tenantId = Guid.NewGuid();
        var userId = Guid.NewGuid();

        // The tenant-less (null) audit chain is installation-global, and this shared local DB may already
        // carry entries (even historical forks from before the fix), so assert on the DELTA this test adds
        // rather than the whole chain's integrity.
        var maxBefore = await MaxNullSequenceAsync(provider);

        // Mimic a Blazor circuit: BOTH a tenant and a user are in scope. Personal-vault operations write
        // tenant-less (TenantId = null) audit entries. Before the fix the null audit chain forked (each op
        // re-sealed sequence 1) because RLS hid the chain head from the writer while a tenant was stamped.
        using (var scope = provider.CreateScope())
        {
            scope.ServiceProvider.GetRequiredService<ITenantScopeSetter>().SetTenant(tenantId);
            scope.ServiceProvider.GetRequiredService<IUserScopeSetter>().SetUser(userId);
            var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
            var vaultId = await vaults.CreatePersonalVaultAsync(new CreatePersonalVaultCommand(userId, "Vault"));
            var itemId = await vaults.AddItemAsync(new AddVaultItemCommand(userId, vaultId, null, ItemType.Login, "GitHub", "u=a;p=b"));
            _ = await vaults.GetItemAsync(userId, itemId); // an audited read
        }

        // The operations must have appended entries with new, DISTINCT sequence numbers past the prior head
        // — not re-sealed sequence 1 (a fork). Assert on entries ABOVE the baseline and require no duplicates
        // there: this is robust to other test methods appending to the same global null chain concurrently
        // (the audit app-lock serializes appends, so a correct chain never duplicates a sequence). Before the
        // fix each of this test's three ops re-sealed an existing low sequence, so duplicates would appear.
        using (var scope = provider.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();

            // Duplicate sequences above the baseline, computed in ONE query so a concurrent append between two
            // round-trips can't make count and distinct inconsistent. Must be 0 — a fork shows up as a dupe.
            var dupesAboveBaseline = await db.Database.SqlQueryRaw<int>(
                "SELECT COUNT(*) - COUNT(DISTINCT [Sequence]) AS [Value] FROM [amkeyward].[AuditEntries] WHERE [TenantId] IS NULL AND [Sequence] > {0}", maxBefore).SingleAsync();
            Assert.AreEqual(0, dupesAboveBaseline, "The tenant-less audit chain has duplicate sequence numbers past the baseline — it forked.");

            // This test appended three tenant-less entries past the head (>= because other test methods may
            // append to the same global chain concurrently; the count only grows, so >= is race-safe).
            var newCount = await db.Database.SqlQueryRaw<int>(
                "SELECT COUNT(*) AS [Value] FROM [amkeyward].[AuditEntries] WHERE [TenantId] IS NULL AND [Sequence] > {0}", maxBefore).SingleAsync();
            Assert.IsGreaterThanOrEqualTo(3, newCount, "This test's three tenant-less audit entries were not appended past the head.");
        }
    }

    private static async Task<long> MaxNullSequenceAsync(ServiceProvider provider)
    {
        using var scope = provider.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
        return await db.Database
            .SqlQueryRaw<long>("SELECT ISNULL(MAX([Sequence]), 0) AS [Value] FROM [amkeyward].[AuditEntries] WHERE [TenantId] IS NULL")
            .SingleAsync();
    }

    [TestMethod, TestCategory("Integration")]
    public async Task System_read_bypass_unblinds_the_maintenance_sweep_over_encrypted_versions()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        await SeedTenantSecretAsync(provider, Guid.NewGuid(), Guid.NewGuid(), "some-value");

        // A tenant-less scope (as the background sweep runs) sees NO secret versions through RLS — every
        // version row has a non-null tenant, so without the bypass the KEK sweep was blind (Checked = 0).
        using (var scope = provider.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
            Assert.AreEqual(0, await db.SecretVersions.IgnoreQueryFilters().CountAsync(),
                "Without the bypass a tenant-less scope must see no secret versions (RLS).");
        }

        // With the system-read bypass on (as the ops monitor sets it before the sweep), the same scope sees
        // them, so the KEK-integrity verifier actually scans rows instead of falsely reporting Checked = 0.
        using (var scope = provider.CreateScope())
        {
            scope.ServiceProvider.GetRequiredService<SystemReadScope>().Enabled = true;
            var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
            Assert.IsGreaterThan(0, await db.SecretVersions.IgnoreQueryFilters().CountAsync(),
                "With the bypass the sweep must see the encrypted version rows.");

            var report = await scope.ServiceProvider.GetRequiredService<IKekIntegrityVerifier>().VerifyAsync();
            Assert.IsGreaterThan(0, report.Checked, "The KEK-integrity verifier must scan rows when the bypass is on.");
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

    private static async Task SeedTenantSecretAsync(ServiceProvider provider, Guid tenantId, Guid projectId, string value)
    {
        using var scope = provider.CreateScope();
        scope.ServiceProvider.GetRequiredService<ITenantScopeSetter>().SetTenant(tenantId);
        var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
        db.Tenants.Add(new Tenant(tenantId, "system", isSystemTenant: true, DateTimeOffset.UtcNow));
        var project = new Project(projectId, tenantId, OwnerType.Tenant, tenantId, "p", DateTimeOffset.UtcNow);
        project.AddEnvironment(Guid.NewGuid(), EnvironmentName.Production, DateTimeOffset.UtcNow);
        db.Projects.Add(project);
        await db.SaveChangesAsync();

        await scope.ServiceProvider.GetRequiredService<ISoftwareSecretService>()
            .StoreAsync(new StoreSoftwareSecretCommand(tenantId, projectId, "Production", "ConnectionStrings:Main", value, null));
    }
}
