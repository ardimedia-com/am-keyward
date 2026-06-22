using System.Security.Cryptography;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Identity;
using Am.Keyward.Infrastructure;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Am.Keyward.Tests;

/// <summary>
/// DSGVO crypto-shredding: an audit entry stores an opaque pseudonym (not the user id), the actor's PII
/// lives encrypted in a separate per-subject row, and erasure destroys the PII while the audit chain stays
/// intact and the pseudonym remains. Runs against a real SQL Server; skips when none is reachable.
/// </summary>
[TestClass]
public class CryptoShreddingTests
{
    private const string ConnectionString = "Server=localhost;Database=amkeyward;Integrated Security=True;Encrypt=False";

    [TestMethod, TestCategory("Integration")]
    public async Task Actor_is_pseudonymized_and_pii_is_crypto_shreddable()
    {
        var services = new ServiceCollection();
        services.AddKeyward(ConnectionString, RandomNumberGenerator.GetBytes(32), "test-kek:v1");
        await using var provider = services.BuildServiceProvider();

        var tenantId = Guid.NewGuid();
        var userId = Guid.NewGuid();
        const string displayName = "Erika Mustermann";

        using (var scope = ScopeFor(provider, tenantId))
        {
            var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
            if (!await db.Database.CanConnectAsync())
            {
                Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
                return;
            }

            db.Users.Add(new AppUser(userId, issuer: null, externalId: userId.ToString("D"), displayName, isSystemAdmin: false, DateTimeOffset.UtcNow));
            await db.SaveChangesAsync();
        }

        // Append two audited events for the same actor (one SaveChanges each).
        using (var scope = ScopeFor(provider, tenantId))
        {
            var audit = scope.ServiceProvider.GetRequiredService<IAuditSink>();
            var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
            for (var i = 0; i < 2; i++)
            {
                await audit.AppendAsync(new AuditRequest(tenantId, AuditAction.Read, "Test", Guid.NewGuid(), userId));
                await db.SaveChangesAsync();
            }
        }

        Guid pseudonymId;
        using (var scope = ScopeFor(provider, tenantId))
        {
            var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
            var actors = await db.AuditEntries
                .Where(a => a.TenantId == tenantId)
                .Select(a => a.ActorPseudonymId)
                .ToListAsync();

            Assert.HasCount(2, actors);
            Assert.IsTrue(actors.All(a => a is not null), "Actor pseudonym should be set.");
            Assert.IsTrue(actors.All(a => a != userId), "Audit must store a pseudonym, not the user id.");
            Assert.AreEqual(1, actors.Distinct().Count(), "The same actor maps to a single stable pseudonym.");
            pseudonymId = actors[0]!.Value;

            // PII is readable through the directory before erasure.
            var pii = await scope.ServiceProvider.GetRequiredService<IAuditSubjectDirectory>().TryReadPiiAsync(pseudonymId);
            Assert.IsNotNull(pii);
            Assert.AreEqual(displayName, pii.DisplayName);

            // ...and is encrypted at rest (the plaintext name never appears in the column).
            var stored = await db.Database
                .SqlQueryRaw<string>("SELECT [EncryptedPii] AS [Value] FROM [amkeyward].[AuditSubjects] WHERE [Id] = {0}", pseudonymId)
                .ToListAsync();
            Assert.IsFalse(stored.Any(s => s.Contains("Mustermann", StringComparison.Ordinal)), "PII must be encrypted at rest.");
        }

        // Erase the subject (DSGVO right to erasure).
        using (var scope = ScopeFor(provider, tenantId))
        {
            var erased = await scope.ServiceProvider.GetRequiredService<IAuditSubjectDirectory>().EraseAsync(userId.ToString("D"));
            Assert.AreEqual(1, erased);
        }

        using (var scope = ScopeFor(provider, tenantId))
        {
            // PII is gone, but the pseudonym and the audit chain survive intact.
            var pii = await scope.ServiceProvider.GetRequiredService<IAuditSubjectDirectory>().TryReadPiiAsync(pseudonymId);
            Assert.IsNull(pii, "PII must be irrecoverable after erasure.");

            var entriesStillReference = await scope.ServiceProvider.GetRequiredService<KeywardDbContext>().AuditEntries
                .CountAsync(a => a.TenantId == tenantId && a.ActorPseudonymId == pseudonymId);
            Assert.AreEqual(2, entriesStillReference, "The pseudonym stays in the audit chain after erasure.");

            var status = await scope.ServiceProvider.GetRequiredService<IAuditChainVerifier>().VerifyAsync(tenantId);
            Assert.IsTrue(status.IsIntact, status.Detail);
        }
    }

    private static IServiceScope ScopeFor(ServiceProvider provider, Guid tenantId)
    {
        var scope = provider.CreateScope();
        scope.ServiceProvider.GetRequiredService<ITenantScopeSetter>().SetTenant(tenantId);
        return scope;
    }
}
