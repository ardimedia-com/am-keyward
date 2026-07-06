using System.Security.Cryptography;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Identity;
using Am.Keyward.Core.Domain.Software;
using Am.Keyward.Core.Domain.ValueObjects;
using Am.Keyward.Infrastructure;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Am.Keyward.Tests;

/// <summary>
/// Adversarial cross-tenant gate. Proves tenant isolation at two independent layers:
/// (1) the application — the central authorization service + tenant scope check + EF query filter; and
/// (2) the database — SQL Server row-level security, exercised through the least-privilege app login
/// (which, unlike the integration test's sysadmin connection, does NOT bypass RLS).
/// Layer (2) runs only when <c>KEYWARD_APP_TEST_CONNECTION</c> points at the <c>amkeyward_app</c> login.
/// </summary>
[TestClass]
public class TenantIsolationTests
{
    private static readonly string ConnectionString = TestConfig.ConnectionString;
    private const string Key = "ConnectionStrings:Main";

    [TestMethod, TestCategory("Integration")]
    public async Task Tenant_cannot_reach_another_tenants_secret_app_layer()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var (t1, p1) = (Guid.NewGuid(), Guid.NewGuid());
        var (t2, p2) = (Guid.NewGuid(), Guid.NewGuid());
        await SeedTenantWithSecretAsync(provider, t1, p1, "tenant-1-secret");
        await SeedTenantWithSecretAsync(provider, t2, p2, "tenant-2-secret");

        using var scope = provider.CreateScope();
        scope.ServiceProvider.GetRequiredService<ITenantScopeSetter>().SetTenant(t1);
        var svc = scope.ServiceProvider.GetRequiredService<ISoftwareSecretService>();
        var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();

        // Own secret is readable inside the tenant scope.
        Assert.AreEqual("tenant-1-secret", await svc.ReadAsync(new ReadSoftwareSecretQuery(t1, p1, "Production", Key, null)));

        // Attack A — claim own tenant but target the other tenant's project: central authorization denies.
        await Assert.ThrowsExactlyAsync<UnauthorizedAccessException>(() =>
            svc.ReadAsync(new ReadSoftwareSecretQuery(t1, p2, "Production", Key, null)));

        // Attack B — claim the other tenant outright: the server-authoritative scope check denies.
        await Assert.ThrowsExactlyAsync<UnauthorizedAccessException>(() =>
            svc.ReadAsync(new ReadSoftwareSecretQuery(t2, p2, "Production", Key, null)));

        // Tenant 1's scope cannot see tenant 2's project at all (neither the query filter nor RLS yields it).
        Assert.IsNull(await db.Projects.FirstOrDefaultAsync(p => p.Id == p2));

        // ...but the row really exists — tenant 2's own scope sees it — so the null above is isolation, not absence.
        using var otherScope = provider.CreateScope();
        otherScope.ServiceProvider.GetRequiredService<ITenantScopeSetter>().SetTenant(t2);
        var otherDb = otherScope.ServiceProvider.GetRequiredService<KeywardDbContext>();
        Assert.IsNotNull(await otherDb.Projects.FirstOrDefaultAsync(p => p.Id == p2));
    }

    [TestMethod, TestCategory("Integration")]
    public async Task RowLevelSecurity_blocks_cross_tenant_reads_for_the_app_login()
    {
        var appConnection = Environment.GetEnvironmentVariable("KEYWARD_APP_TEST_CONNECTION");
        if (string.IsNullOrWhiteSpace(appConnection))
        {
            Assert.Inconclusive("Set KEYWARD_APP_TEST_CONNECTION (amkeyward_app login) to verify SQL Server row-level security.");
            return;
        }

        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var (t1, p1) = (Guid.NewGuid(), Guid.NewGuid());
        var (t2, p2) = (Guid.NewGuid(), Guid.NewGuid());
        await SeedTenantWithSecretAsync(provider, t1, p1, "tenant-1-secret");
        await SeedTenantWithSecretAsync(provider, t2, p2, "tenant-2-secret");

        // The least-privilege login does not bypass RLS: each session sees only its own tenant's rows,
        // even though both projects physically exist.
        Assert.AreEqual(1, await CountVisibleProjectsAsync(appConnection, sessionTenant: t1, p1, p2));
        Assert.AreEqual(1, await CountVisibleProjectsAsync(appConnection, sessionTenant: t2, p1, p2));
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

    private static async Task SeedTenantWithSecretAsync(ServiceProvider provider, Guid tenantId, Guid projectId, string value)
    {
        using var scope = provider.CreateScope();
        scope.ServiceProvider.GetRequiredService<ITenantScopeSetter>().SetTenant(tenantId);

        var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
        db.Tenants.Add(new Tenant(tenantId, "system", isSystemTenant: true, DateTimeOffset.UtcNow));
        var project = new Project(projectId, tenantId, OwnerType.Tenant, tenantId, "isolation", DateTimeOffset.UtcNow);
        project.AddEnvironment(Guid.NewGuid(), EnvironmentName.Production, DateTimeOffset.UtcNow);
        db.Projects.Add(project);
        await db.SaveChangesAsync();

        await scope.ServiceProvider.GetRequiredService<ISoftwareSecretService>()
            .StoreAsync(new StoreSoftwareSecretCommand(tenantId, projectId, "Production", Key, value, null));
    }

    private static async Task<int> CountVisibleProjectsAsync(string connectionString, Guid sessionTenant, Guid a, Guid b)
    {
        await using var connection = new SqlConnection(connectionString);
        await connection.OpenAsync();

        await using (var setContext = connection.CreateCommand())
        {
            setContext.CommandText = "EXEC sp_set_session_context @key = N'TenantId', @value = @tenant;";
            setContext.Parameters.Add(new SqlParameter("@tenant", sessionTenant));
            await setContext.ExecuteNonQueryAsync();
        }

        await using var count = connection.CreateCommand();
        count.CommandText = "SELECT COUNT(*) FROM amkeyward.Projects WHERE Id IN (@a, @b);";
        count.Parameters.Add(new SqlParameter("@a", a));
        count.Parameters.Add(new SqlParameter("@b", b));
        return (int)(await count.ExecuteScalarAsync())!;
    }
}
