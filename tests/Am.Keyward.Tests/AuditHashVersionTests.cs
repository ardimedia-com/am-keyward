using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Audit;
using Am.Keyward.Infrastructure;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Am.Keyward.Tests;

/// <summary>
/// Audit hash versioning: version 1 stays byte-for-byte what existing chains were sealed with, version 2 covers
/// the actor kind, token and free-text reason unambiguously, and a chain that spans both verifies end to end
/// while any change to the new fields is detected.
/// </summary>
[TestClass]
public class AuditHashVersionTests
{
    private static readonly string ConnectionString = TestConfig.ConnectionString;

    private static readonly DateTimeOffset At = new(2026, 9, 25, 18, 30, 0, TimeSpan.Zero);

    [TestMethod, TestCategory("Unit")]
    public void Version1_hash_is_unchanged()
    {
        var tenantId = Guid.NewGuid();
        var resourceId = Guid.NewGuid();
        var actor = Guid.NewGuid();
        var entry = Entry(hashVersion: 1, tenantId, AuditAction.Update, "VaultItem", resourceId, actor, kind: null, token: null, reason: null);

        Assert.AreEqual(
            LegacyV1(tenantId, 7, AuditAction.Update, "VaultItem", resourceId, actor, At, AuditChainHash.GenesisHash),
            AuditChainHash.Compute(entry, 7, AuditChainHash.GenesisHash));
    }

    [TestMethod, TestCategory("Unit")]
    public void Version2_distinguishes_every_reason_and_the_new_fields()
    {
        string Hash(ActorKind? kind, Guid? token, string? reason) =>
            AuditChainHash.Compute(Entry(2, null, AuditAction.Reveal, "VaultItem", null, null, kind, token, reason), 1, AuditChainHash.GenesisHash);

        var token = Guid.NewGuid();
        string[] hashes =
        [
            Hash(ActorKind.Agent, token, null),
            Hash(ActorKind.Agent, token, "-"),
            Hash(ActorKind.Agent, token, ""),
            Hash(ActorKind.Agent, token, "a|b"),
            Hash(ActorKind.Agent, token, "a"),
            Hash(ActorKind.User, token, null),
            Hash(ActorKind.Agent, null, null),
            Hash(null, token, null),
        ];

        Assert.AreEqual(hashes.Length, hashes.Distinct().Count(), "Two different field combinations produced the same hash.");

        // Same fields as a v1 entry must not hash alike: the version is part of the input.
        var v1 = AuditChainHash.Compute(Entry(1, null, AuditAction.Reveal, "VaultItem", null, null, null, null, null), 1, AuditChainHash.GenesisHash);
        var v2 = AuditChainHash.Compute(Entry(2, null, AuditAction.Reveal, "VaultItem", null, null, null, null, null), 1, AuditChainHash.GenesisHash);
        Assert.AreNotEqual(v1, v2);
    }

    [TestMethod, TestCategory("Unit")]
    public void Unknown_hash_version_is_rejected()
    {
        var entry = Entry(99, null, AuditAction.Read, "X", null, null, null, null, null);
        Assert.ThrowsExactly<InvalidOperationException>(() => AuditChainHash.Compute(entry, 1, AuditChainHash.GenesisHash));
    }

    [TestMethod, TestCategory("Unit")]
    public void Overlong_reason_is_rejected()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            Entry(2, null, AuditAction.Read, "X", null, null, ActorKind.User, null, new string('x', AuditEntry.MaxReasonLength + 1)));
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Chain_spanning_versions_verifies_and_new_fields_are_tamper_evident()
    {
        var services = new ServiceCollection();
        services.AddKeyward(ConnectionString, RandomNumberGenerator.GetBytes(32), "test-kek:v1");
        await using var provider = services.BuildServiceProvider();

        using (var probe = provider.CreateScope())
        {
            if (!await probe.ServiceProvider.GetRequiredService<KeywardDbContext>().Database.CanConnectAsync())
            {
                Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
                return;
            }
        }

        var tenantId = Guid.NewGuid();
        var agentToken = Guid.NewGuid();

        // Two rows sealed the way every entry was before hash versioning existed.
        using (var scope = ScopeFor(provider, tenantId))
        {
            var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
            var previous = AuditChainHash.GenesisHash;
            for (long sequence = 1; sequence <= 2; sequence++)
            {
                var resourceId = Guid.NewGuid();
                var hash = LegacyV1(tenantId, sequence, AuditAction.Read, "Legacy", resourceId, null, At, previous);
                await db.Database.ExecuteSqlRawAsync(
                    "INSERT INTO [amkeyward].[AuditEntries] ([Id],[TenantId],[Sequence],[Action],[ResourceType],[ResourceId],[ActorPseudonymId],[OccurredAt],[PreviousHash],[Hash]) "
                    + "VALUES ({0},{1},{2},'Read','Legacy',{3},NULL,{4},{5},{6})",
                    Guid.NewGuid(), tenantId, sequence, resourceId, At, previous, hash);
                previous = hash;
            }
        }

        // Current entries: a system call, an agent call with free-text reasons that contain the delimiter.
        using (var scope = ScopeFor(provider, tenantId))
        {
            var audit = scope.ServiceProvider.GetRequiredService<IAuditSink>();
            var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
            await audit.AppendAsync(new AuditRequest(tenantId, AuditAction.Update, "Test", Guid.NewGuid(), null));
            await db.SaveChangesAsync();
        }

        using (var scope = ScopeFor(provider, tenantId))
        {
            scope.ServiceProvider.GetRequiredService<IActorScopeSetter>().SetActor(ActorKind.Agent, agentToken);
            var audit = scope.ServiceProvider.GetRequiredService<IAuditSink>();
            var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
            foreach (var reason in new[] { "CH-Post | setup für Übergabe", "-", "" })
            {
                await audit.AppendAsync(new AuditRequest(tenantId, AuditAction.RevealRequested, "RevealRequest", Guid.NewGuid(), null, reason));
                await db.SaveChangesAsync();
            }
        }

        using (var scope = ScopeFor(provider, tenantId))
        {
            var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
            var rows = await db.AuditEntries.AsNoTracking().Where(a => a.TenantId == tenantId).OrderBy(a => a.Sequence).ToListAsync();
            Assert.AreEqual(6, rows.Count);
            Assert.AreEqual(1, rows[1].HashVersion);
            Assert.IsNull(rows[1].ActorKind);
            Assert.AreEqual(AuditEntry.CurrentHashVersion, rows[2].HashVersion);
            Assert.AreEqual(ActorKind.System, rows[2].ActorKind);
            Assert.AreEqual(ActorKind.Agent, rows[3].ActorKind);
            Assert.AreEqual(agentToken, rows[3].ActorTokenId);
            Assert.AreEqual("CH-Post | setup für Übergabe", rows[3].Reason);

            var status = await scope.ServiceProvider.GetRequiredService<IAuditChainVerifier>().VerifyAsync(tenantId);
            Assert.IsTrue(status.IsIntact, status.Detail);
            Assert.AreEqual(6L, status.EntriesChecked);
        }

        // Each new field is covered by the hash: altering it breaks the chain at that entry.
        (string Column, string Tampered)[] tampering =
        [
            ("Reason", "'something else'"),
            ("ActorKind", "'User'"),
            ("ActorTokenId", "'" + Guid.NewGuid() + "'"),
            ("HashVersion", "1"),
        ];
        foreach (var (column, tampered) in tampering)
        {
            await TamperAndVerifyAsync(provider, tenantId, sequence: 4, column, tampered);
        }
    }

    private static async Task TamperAndVerifyAsync(ServiceProvider provider, Guid tenantId, long sequence, string column, string tampered)
    {
        using var scope = ScopeFor(provider, tenantId);
        var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
        var original = await db.AuditEntries.AsNoTracking().SingleAsync(a => a.TenantId == tenantId && a.Sequence == sequence);

        // Column names and values are test constants, not input.
#pragma warning disable EF1003
        await db.Database.ExecuteSqlRawAsync(
            "UPDATE [amkeyward].[AuditEntries] SET [" + column + "] = " + tampered + " WHERE [TenantId] = {0} AND [Sequence] = {1}",
            tenantId, sequence);
#pragma warning restore EF1003

        var status = await scope.ServiceProvider.GetRequiredService<IAuditChainVerifier>().VerifyAsync(tenantId);
        Assert.IsFalse(status.IsIntact, $"Changing {column} was not detected.");
        Assert.AreEqual(sequence, status.FirstBrokenSequence, column);

        // Restore, so the next field is tampered on an otherwise intact chain.
        await db.Database.ExecuteSqlRawAsync(
            "UPDATE [amkeyward].[AuditEntries] SET [Reason] = {0}, [ActorKind] = {1}, [ActorTokenId] = {2}, [HashVersion] = {3} "
            + "WHERE [TenantId] = {4} AND [Sequence] = {5}",
            (object?)original.Reason ?? DBNull.Value, (object?)original.ActorKind?.ToString() ?? DBNull.Value,
            (object?)original.ActorTokenId ?? DBNull.Value, original.HashVersion, tenantId, sequence);
        Assert.IsTrue((await scope.ServiceProvider.GetRequiredService<IAuditChainVerifier>().VerifyAsync(tenantId)).IsIntact);
    }

    private static AuditEntry Entry(int hashVersion, Guid? tenantId, AuditAction action, string resourceType, Guid? resourceId,
        Guid? actor, ActorKind? kind, Guid? token, string? reason) =>
        new(Guid.NewGuid(), tenantId, 0, action, resourceType, resourceId, actor, At, AuditChainHash.GenesisHash, "",
            hashVersion, kind, token, reason);

    // An independent copy of the original (version 1) canonical form, as it was before hash versioning. If
    // AuditChainHash ever changes how version 1 is computed, existing production chains stop verifying.
    private static string LegacyV1(Guid? tenantId, long sequence, AuditAction action, string resourceType,
        Guid? resourceId, Guid? actorPseudonymId, DateTimeOffset occurredAt, string previousHash)
    {
        var canonical = string.Join('|',
        [
            tenantId?.ToString("D") ?? "-",
            sequence.ToString(CultureInfo.InvariantCulture),
            action.ToString(),
            resourceType,
            resourceId?.ToString("D") ?? "-",
            actorPseudonymId?.ToString("D") ?? "-",
            occurredAt.ToString("O"),
            previousHash,
        ]);
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    private static IServiceScope ScopeFor(ServiceProvider provider, Guid tenantId)
    {
        var scope = provider.CreateScope();
        scope.ServiceProvider.GetRequiredService<ITenantScopeSetter>().SetTenant(tenantId);
        return scope;
    }
}
