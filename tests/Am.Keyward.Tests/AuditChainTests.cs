using System.Security.Cryptography;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Domain;
using Am.Keyward.Infrastructure;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Am.Keyward.Tests;

/// <summary>
/// The per-tenant audit hash chain is verifiable: an intact chain validates, and altering any entry's
/// stored hash is detected at that sequence. Runs against a real SQL Server; skips when none is reachable.
/// </summary>
[TestClass]
public class AuditChainTests
{
    private const string ConnectionString = "Server=localhost;Database=amkeyward;Integrated Security=True;Encrypt=False";

    [TestMethod, TestCategory("Integration")]
    public async Task Intact_chain_verifies_and_tampering_is_detected()
    {
        var services = new ServiceCollection();
        services.AddKeyward(ConnectionString, RandomNumberGenerator.GetBytes(32), "test-kek:v1");
        await using var provider = services.BuildServiceProvider();

        var tenantId = Guid.NewGuid();

        using (var probe = provider.CreateScope())
        {
            if (!await probe.ServiceProvider.GetRequiredService<KeywardDbContext>().Database.CanConnectAsync())
            {
                Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
                return;
            }
        }

        // Append three audited events (each persisted on its own SaveChanges, as in real operations).
        using (var scope = ScopeFor(provider, tenantId))
        {
            var audit = scope.ServiceProvider.GetRequiredService<IAuditSink>();
            var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
            for (var i = 0; i < 3; i++)
            {
                await audit.AppendAsync(new AuditRequest(tenantId, AuditAction.Read, "Test", Guid.NewGuid(), null));
                await db.SaveChangesAsync();
            }
        }

        using (var scope = ScopeFor(provider, tenantId))
        {
            var status = await scope.ServiceProvider.GetRequiredService<IAuditChainVerifier>().VerifyAsync(tenantId);
            Assert.IsTrue(status.IsIntact, status.Detail);
            Assert.AreEqual(3L, status.EntriesChecked);
        }

        // Tamper with the second entry's stored hash.
        using (var scope = ScopeFor(provider, tenantId))
        {
            var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
            await db.Database.ExecuteSqlRawAsync(
                "UPDATE [amkeyward].[AuditEntries] SET [Hash] = {0} WHERE [TenantId] = {1} AND [Sequence] = 2",
                new string('f', 64), tenantId);
        }

        using (var scope = ScopeFor(provider, tenantId))
        {
            var status = await scope.ServiceProvider.GetRequiredService<IAuditChainVerifier>().VerifyAsync(tenantId);
            Assert.IsFalse(status.IsIntact);
            Assert.AreEqual(2L, status.FirstBrokenSequence);
        }
    }

    private static IServiceScope ScopeFor(ServiceProvider provider, Guid tenantId)
    {
        var scope = provider.CreateScope();
        scope.ServiceProvider.GetRequiredService<ITenantScopeSetter>().SetTenant(tenantId);
        return scope;
    }
}
