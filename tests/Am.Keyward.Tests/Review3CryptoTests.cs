using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Identity;
using Am.Keyward.Core.Domain.Software;
using Am.Keyward.Core.Domain.ValueObjects;
using Am.Keyward.Infrastructure;
using Am.Keyward.Infrastructure.Auth;
using Am.Keyward.Infrastructure.Crypto;
using Am.Keyward.Infrastructure.Monitoring;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using NSubstitute;

namespace Am.Keyward.Tests;

/// <summary>
/// Review 3, area «crypto, key custody, trails»: first-run key creation is exclusive and protected, the key ring opens
/// legacy ids, the re-wrap job moves data keys to the current KEK, the ownership canary is re-evaluated and refuses a
/// database that already holds foreign ciphertext, the break-glass trail survives a torn line and several writers,
/// and the audit-chain verifier works incrementally and against out-of-band anchors.
/// </summary>
[TestClass]
public class Review3CryptoTests
{
    private static readonly string ConnectionString = TestConfig.ConnectionString;

    // ---- M5: key ring and legacy ids --------------------------------------------------------------------------------

    [TestMethod, TestCategory("Crypto")]
    public async Task Key_ring_opens_a_legacy_unqualified_id_with_the_member_that_sealed_it()
    {
        const string Format = "dpapi-file:v1";
        var keyA = RandomNumberGenerator.GetBytes(32);
        var keyB = RandomNumberGenerator.GetBytes(32);
        var dek = RandomNumberGenerator.GetBytes(32);

        // A row written before the fingerprint existed: sealed by key A, stored under the bare format id.
        var wrappedUnderLegacyId = await new StaticKekProvider(keyA, Format).WrapAsync(dek);

        var ring = new KeyRingKekProvider(KekFingerprint.Qualify(Format, keyB), new Dictionary<string, byte[]>
        {
            [KekFingerprint.Qualify(Format, keyA)] = keyA,
            [KekFingerprint.Qualify(Format, keyB)] = keyB,
        });

        Assert.IsTrue(ring.CanResolve(Format), "The bare format id of a ring member resolves.");
        CollectionAssert.AreEqual(dek, await ring.UnwrapAsync(wrappedUnderLegacyId, Format),
            "The trial over the candidates finds key A although the current key is B.");

        var ringWithoutA = new KeyRingKekProvider(KekFingerprint.Qualify(Format, keyB), new Dictionary<string, byte[]>
        {
            [KekFingerprint.Qualify(Format, keyB)] = keyB,
        });
        Assert.IsTrue(ringWithoutA.CanResolve(Format), "The id alone cannot tell the keys apart ...");
        await Assert.ThrowsAsync<CryptographicException>(async () => await ringWithoutA.UnwrapAsync(wrappedUnderLegacyId, Format),
            "... but GCM authentication can: a foreign key never yields a data key.");
        Assert.IsFalse(ring.CanResolve("other-format:v1"));
    }

    // ---- M5: the re-wrap job ----------------------------------------------------------------------------------------

    [TestMethod, TestCategory("Integration")]
    public async Task Rewrap_moves_every_data_key_to_the_current_kek_so_the_old_key_can_be_retired()
    {
        var oldId = $"rewrap-old:{Guid.NewGuid():N}";
        var newId = $"rewrap-new:{Guid.NewGuid():N}";
        var oldKey = RandomNumberGenerator.GetBytes(32);
        var newKey = RandomNumberGenerator.GetBytes(32);
        var tenantId = Guid.NewGuid();
        var projectId = Guid.NewGuid();

        await using var before = Provider(ConnectionString, new KeyRingKekProvider(oldId, new Dictionary<string, byte[]> { [oldId] = oldKey }));
        if (!await CanConnectAsync(before))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        await SeedProjectAsync(before, tenantId, projectId);
        using (var scope = ScopeFor(before, tenantId))
        {
            await scope.ServiceProvider.GetRequiredService<ISoftwareSecretService>()
                .StoreAsync(new StoreSoftwareSecretCommand(tenantId, projectId, "Production", "Api:Key", "the value", null));
        }

        // Rotate: the new key is current, the old one stays in the ring until the re-wrap ran.
        await using var rotated = Provider(ConnectionString, new KeyRingKekProvider(newId, new Dictionary<string, byte[]>
        {
            [oldId] = oldKey,
            [newId] = newKey,
        }));
        var rewrap = rotated.GetRequiredService<KekRewrapService>();
        var report = await rewrap.RewrapAsync(batchSize: 2);
        Assert.AreEqual(newId, report.TargetKekId);
        Assert.IsGreaterThanOrEqualTo(1, report.Rewrapped);
        Assert.IsFalse(report.Unresolvable.Any(u => u.KekId == oldId), "Everything under the old key was movable.");

        // Idempotent: a second run finds nothing of ours left.
        var again = await rewrap.RewrapAsync();
        Assert.IsFalse(again.Unresolvable.Any(u => u.KekId == oldId || u.KekId == newId));

        // The old key is retired: a ring holding ONLY the new key reads the value.
        await using var retired = Provider(ConnectionString, new KeyRingKekProvider(newId, new Dictionary<string, byte[]> { [newId] = newKey }));
        using (var scope = ScopeFor(retired, tenantId))
        {
            var value = await scope.ServiceProvider.GetRequiredService<ISoftwareSecretService>()
                .ReadAsync(new ReadSoftwareSecretQuery(tenantId, projectId, "Production", "Api:Key", null));
            Assert.AreEqual("the value", value);

            var chain = await scope.ServiceProvider.GetRequiredService<IAuditChainVerifier>().VerifyAsync(tenantId);
            Assert.IsTrue(chain.IsIntact, chain.Detail);

            var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
            Assert.IsTrue(await db.AuditEntries.AnyAsync(a => a.TenantId == tenantId && a.ResourceType == KekRewrapService.AuditResourceType),
                "Each re-wrapped batch is audited in its tenant's chain.");
        }
    }

    // ---- M4: the canary refuses a database that already holds foreign ciphertext ------------------------------------

    [TestMethod, TestCategory("Integration")]
    public async Task Canary_is_not_written_into_a_database_that_holds_values_of_another_key()
    {
        await using var database = await IsolatedDatabase.CreateAsync();
        if (database is null)
        {
            Assert.Inconclusive("SQL Server not reachable or no right to create a database — skipping.");
            return;
        }

        var tenantId = Guid.NewGuid();
        var projectId = Guid.NewGuid();
        await using var owner = Provider(database.ConnectionString, new StaticKekProvider(RandomNumberGenerator.GetBytes(32), "owner:v1"));
        await SeedProjectAsync(owner, tenantId, projectId);
        using (var scope = ScopeFor(owner, tenantId))
        {
            await scope.ServiceProvider.GetRequiredService<ISoftwareSecretService>()
                .StoreAsync(new StoreSoftwareSecretCommand(tenantId, projectId, "Production", "Db:Password", "s3cret", null));
        }

        // A second installation with ANOTHER key reaches the database first after the canary feature arrived.
        await using var intruder = Provider(database.ConnectionString, new StaticKekProvider(RandomNumberGenerator.GetBytes(32), "intruder:v1"));
        var intruderState = intruder.GetRequiredService<KeywardKeyIntegrityState>();
        Assert.AreEqual(KekIntegrityStatus.Conflict, await intruderState.RecheckAsync());
        StringAssert.Contains(intruderState.Detail, "owner:v1");
        Assert.IsTrue(intruderState.IsBlocked);
        Assert.AreEqual(0, await CanaryCountAsync(database.ConnectionString), "No canary may be claimed by the wrong key.");

        // The owning key claims it, and verifies it afterwards.
        var ownerState = owner.GetRequiredService<KeywardKeyIntegrityState>();
        Assert.AreEqual(KekIntegrityStatus.Created, await ownerState.RecheckAsync());
        Assert.AreEqual(KekIntegrityStatus.Ok, await ownerState.RecheckAsync());
        Assert.AreEqual(KekIntegrityStatus.Conflict, await intruderState.RecheckAsync());
    }

    // ---- M3: an Unknown verdict is re-evaluated ---------------------------------------------------------------------

    [TestMethod, TestCategory("Integration")]
    public async Task An_unknown_verdict_is_rechecked_on_the_first_use_of_the_key()
    {
        await using var database = await IsolatedDatabase.CreateAsync();
        if (database is null)
        {
            Assert.Inconclusive("SQL Server not reachable or no right to create a database — skipping.");
            return;
        }

        var aad = Encoding.UTF8.GetBytes("slot");
        await using var first = Provider(database.ConnectionString, new StaticKekProvider(RandomNumberGenerator.GetBytes(32), "first:v1"));
        var state = first.GetRequiredService<KeywardKeyIntegrityState>();

        // The startup check ran while the database was down.
        state.Record(KekIntegrityStatus.Unknown, "simulated: database unreachable at start");

        // Many concurrent first uses: ONE recheck, and it writes the canary.
        using (var scope = first.CreateScope())
        {
            var backend = scope.ServiceProvider.GetRequiredService<ISecretBackend>();
            await Task.WhenAll(Enumerable.Range(0, 8).Select(async _ => await backend.ProtectAsync("v"u8.ToArray(), aad)));
        }

        Assert.AreEqual(KekIntegrityStatus.Created, state.Status);
        Assert.AreEqual(1, await CanaryCountAsync(database.ConnectionString));

        // Another key on the same database, also Unknown at start: the first use is refused, not written.
        await using var second = Provider(database.ConnectionString, new StaticKekProvider(RandomNumberGenerator.GetBytes(32), "second:v1"));
        second.GetRequiredService<KeywardKeyIntegrityState>().Record(KekIntegrityStatus.Unknown, "simulated");
        using (var scope = second.CreateScope())
        {
            var backend = scope.ServiceProvider.GetRequiredService<ISecretBackend>();
            await Assert.ThrowsExactlyAsync<KeywardKeyMismatchException>(async () => await backend.ProtectAsync("v"u8.ToArray(), aad));
        }
    }

    [TestMethod, TestCategory("Unit")]
    public async Task A_state_that_never_ran_a_check_does_not_recheck_on_use()
    {
        // Hand-wired state (no scope factory) and a DI state that never recorded a verdict both stay inert.
        var state = new KeywardKeyIntegrityState(Options.Create(new KeywardKeyIntegrityOptions()));
        await state.EnsureVerifiedAsync();
        Assert.AreEqual(KekIntegrityStatus.Unknown, state.Status);
        await Assert.ThrowsExactlyAsync<InvalidOperationException>(async () => await state.RecheckAsync());
    }

    // ---- M6: break-glass trail --------------------------------------------------------------------------------------

    [TestMethod, TestCategory("Unit")]
    public async Task Break_glass_trail_survives_a_torn_last_line_and_reports_it()
    {
        var path = TempFile();
        try
        {
            var sink = new FileBreakGlassSink(Options.Create(new BreakGlassOptions { SinkFilePath = path }));
            await sink.AppendAsync(Record("Requested"));

            // A crash mid-append: half a line, no newline.
            await File.AppendAllTextAsync(path, "{\"record\":{\"at\":\"2026-");

            // A NEW instance (another process, or after a restart) keeps appending instead of failing forever.
            var afterCrash = new FileBreakGlassSink(Options.Create(new BreakGlassOptions { SinkFilePath = path }));
            await afterCrash.AppendAsync(Record("Approved"));
            await afterCrash.AppendAsync(Record("Consumed"));

            var verification = await afterCrash.VerifyAsync();
            Assert.IsTrue(verification.IsIntact, verification.Detail);
            Assert.AreEqual(3, verification.ValidLines);
            CollectionAssert.AreEqual(new[] { 2 }, verification.DamagedLines.ToArray(), "The torn line is reported, not hidden.");
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod, TestCategory("Unit")]
    public async Task Two_writers_on_one_trail_never_fork_the_chain_and_tampering_is_detected()
    {
        var path = TempFile();
        try
        {
            var a = new FileBreakGlassSink(Options.Create(new BreakGlassOptions { SinkFilePath = path }));
            var b = new FileBreakGlassSink(Options.Create(new BreakGlassOptions { SinkFilePath = path }));
            await Task.WhenAll(Enumerable.Range(0, 20).Select(i => (i % 2 == 0 ? a : b).AppendAsync(Record($"E{i}"))));

            var verification = await a.VerifyAsync();
            Assert.IsTrue(verification.IsIntact, verification.Detail);
            Assert.AreEqual(20, verification.ValidLines);

            // Edit one event's reason: the line no longer recomputes.
            var lines = await File.ReadAllLinesAsync(path);
            lines[5] = lines[5].Replace("\"reason\":\"why\"", "\"reason\":\"other\"", StringComparison.Ordinal);
            await File.WriteAllLinesAsync(path, lines);

            var tampered = await a.VerifyAsync();
            Assert.IsFalse(tampered.IsIntact);
            Assert.AreEqual(6, tampered.FirstBrokenLine);
        }
        finally
        {
            File.Delete(path);
            File.Delete(path + ".lock");
        }
    }

    [TestMethod, TestCategory("Unit")]
    public async Task Break_glass_trail_written_by_the_previous_version_verifies_and_continues()
    {
        var path = TempFile();
        try
        {
            // The pre-0.39 sink serialized the whole line with the web defaults; the chain format is unchanged.
            var json = new JsonSerializerOptions(JsonSerializerDefaults.Web);
            var genesis = new string('0', 64);
            var record = Record("Requested");
            var canonical = JsonSerializer.Serialize(record, json);
            var hash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(genesis + '|' + canonical)));
            await File.WriteAllTextAsync(path, JsonSerializer.Serialize(new { record, prevHash = genesis, hash }, json) + Environment.NewLine);

            var sink = new FileBreakGlassSink(Options.Create(new BreakGlassOptions { SinkFilePath = path }));
            await sink.AppendAsync(Record("Approved"));

            var verification = await sink.VerifyAsync();
            Assert.IsTrue(verification.IsIntact, verification.Detail);
            Assert.AreEqual(2, verification.ValidLines);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod, TestCategory("Unit")]
    public void Break_glass_path_is_required_outside_development()
    {
        var production = Substitute.For<IHostEnvironment>();
        production.EnvironmentName.Returns(Environments.Production);
        var development = Substitute.For<IHostEnvironment>();
        development.EnvironmentName.Returns(Environments.Development);

        var unset = new BreakGlassOptions();
        var refused = Assert.ThrowsExactly<InvalidOperationException>(() => unset.ResolveSinkFilePath(production));
        StringAssert.Contains(refused.Message, "SinkFilePath");
        Assert.ThrowsExactly<InvalidOperationException>(() => unset.ResolveSinkFilePath(null));
        Assert.AreEqual(Path.Combine(Directory.GetCurrentDirectory(), BreakGlassOptions.DefaultSinkFileName), unset.ResolveSinkFilePath(development));
        Assert.IsNull(unset.ResolveAuditAnchorFilePath(), "No out-of-band path configured: no anchors.");

        var configured = new BreakGlassOptions { SinkFilePath = Path.Combine(Path.GetTempPath(), "kw", "bg.jsonl") };
        Assert.AreEqual(configured.SinkFilePath, configured.ResolveSinkFilePath(production));
        Assert.AreEqual(Path.Combine(Path.GetTempPath(), "kw", BreakGlassOptions.DefaultAuditAnchorFileName), configured.ResolveAuditAnchorFilePath());
        Assert.IsNull(new BreakGlassOptions { SinkFilePath = configured.SinkFilePath, AuditAnchorsEnabled = false }.ResolveAuditAnchorFilePath());
    }

    [TestMethod, TestCategory("Unit")]
    public async Task Host_start_fails_outside_development_without_a_break_glass_path_and_post_configure_still_counts()
    {
        var missing = Host.CreateEmptyApplicationBuilder(new HostApplicationBuilderSettings { EnvironmentName = Environments.Production });
        missing.Services.AddKeyward("Server=unused;Database=unused", RandomNumberGenerator.GetBytes(32), "test-kek:v1");
        missing.Services.RemoveAllHostedServices();
        using (var host = missing.Build())
        {
            var refused = await Assert.ThrowsAsync<OptionsValidationException>(() => host.StartAsync());
            StringAssert.Contains(refused.Message, "SinkFilePath");
        }

        var postConfigured = Host.CreateEmptyApplicationBuilder(new HostApplicationBuilderSettings { EnvironmentName = Environments.Production });
        postConfigured.Services.AddKeyward("Server=unused;Database=unused", RandomNumberGenerator.GetBytes(32), "test-kek:v1");
        postConfigured.Services.PostConfigure<BreakGlassOptions>(o => o.SinkFilePath = TempFile());
        postConfigured.Services.RemoveAllHostedServices();
        using (var host = postConfigured.Build())
        {
            await host.StartAsync();
            await host.StopAsync();
        }
    }

    // ---- M14 + LOW: incremental audit verification and head anchors -------------------------------------------------

    [TestMethod, TestCategory("Integration")]
    public async Task Audit_chain_verifies_incrementally_and_fails_when_behind_its_anchor()
    {
        var folder = Path.Combine(Path.GetTempPath(), "keyward-anchor-test-" + Guid.NewGuid().ToString("N"));
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddKeyward(ConnectionString, RandomNumberGenerator.GetBytes(32), "test-kek:v1");
        services.Configure<BreakGlassOptions>(o => o.SinkFilePath = Path.Combine(folder, "bg.jsonl"));
        await using var provider = services.BuildServiceProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var tenantId = Guid.NewGuid();
        try
        {
            await AppendAuditAsync(provider, tenantId, 3);

            var anchors = provider.GetRequiredService<AuditHeadAnchorLog>();
            var checkpoints = provider.GetRequiredService<AuditChainCheckpoints>();
            Assert.IsTrue(anchors.IsEnabled);

            using (var scope = ScopeFor(provider, tenantId))
            {
                var verifier = (DbAuditChainVerifier)scope.ServiceProvider.GetRequiredService<IAuditChainVerifier>();
                var full = await verifier.VerifyAsync(tenantId, full: true);
                Assert.IsTrue(full.IsIntact, full.Detail);
                Assert.AreEqual(3L, full.EntriesChecked);
                Assert.IsTrue(checkpoints.TryGet(tenantId, out var sequence, out var hash));
                Assert.AreEqual(3L, sequence);
                Assert.IsTrue(await anchors.RecordAsync(tenantId, sequence, hash));
                Assert.IsFalse(await anchors.RecordAsync(tenantId, sequence, hash), "An unchanged head is not anchored twice.");
            }

            // Two more entries: the hourly pass walks only those.
            await AppendAuditAsync(provider, tenantId, 2);
            using (var scope = ScopeFor(provider, tenantId))
            {
                var verifier = (DbAuditChainVerifier)scope.ServiceProvider.GetRequiredService<IAuditChainVerifier>();
                var incremental = await verifier.VerifyAsync(tenantId, full: false);
                Assert.IsTrue(incremental.IsIntact, incremental.Detail);
                Assert.AreEqual(5L, incremental.EntriesChecked);
            }

            // Cut the last three entries off: the remaining prefix is a valid chain, the anchor at 3 says otherwise.
            using (var scope = ScopeFor(provider, tenantId))
            {
                var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
                await db.Database.ExecuteSqlRawAsync(
                    "DELETE FROM [amkeyward].[AuditEntries] WHERE [TenantId] = {0} AND [Sequence] >= 3", tenantId);

                var verifier = (DbAuditChainVerifier)scope.ServiceProvider.GetRequiredService<IAuditChainVerifier>();
                var truncated = await verifier.VerifyAsync(tenantId, full: false);
                Assert.IsFalse(truncated.IsIntact);
                StringAssert.Contains(truncated.Detail, "anchor");
                Assert.AreEqual(2L, truncated.EntriesChecked);
            }

            var trail = await anchors.VerifyAsync();
            Assert.IsTrue(trail.IsIntact, trail.Detail);
            Assert.AreEqual(1, trail.ValidLines);
        }
        finally
        {
            if (Directory.Exists(folder))
            {
                Directory.Delete(folder, recursive: true);
            }
        }
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Incremental_verification_falls_back_to_a_full_walk_when_the_checkpoint_entry_changed()
    {
        var services = new ServiceCollection();
        services.AddKeyward(ConnectionString, RandomNumberGenerator.GetBytes(32), "test-kek:v1");
        await using var provider = services.BuildServiceProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var tenantId = Guid.NewGuid();
        await AppendAuditAsync(provider, tenantId, 3);
        using var scope = ScopeFor(provider, tenantId);
        var verifier = (DbAuditChainVerifier)scope.ServiceProvider.GetRequiredService<IAuditChainVerifier>();
        Assert.IsTrue((await verifier.VerifyAsync(tenantId, full: true)).IsIntact);

        // Rewrite the checkpoint entry's hash (as a rewrite of anything before it would have to).
        var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
        await db.Database.ExecuteSqlRawAsync(
            "UPDATE [amkeyward].[AuditEntries] SET [Hash] = {0} WHERE [TenantId] = {1} AND [Sequence] = 3",
            new string('e', 64), tenantId);

        var status = await verifier.VerifyAsync(tenantId, full: false);
        Assert.IsFalse(status.IsIntact);
        Assert.AreEqual(3L, status.FirstBrokenSequence);
    }

    // ---- Health -----------------------------------------------------------------------------------------------------

    [TestMethod, TestCategory("Unit")]
    public async Task Health_is_unhealthy_on_a_key_conflict_or_a_broken_trail_and_degraded_on_damaged_lines()
    {
        var now = new DateTimeOffset(2026, 11, 11, 12, 0, 0, TimeSpan.Zero);
        var clock = Substitute.For<IClock>();
        clock.UtcNow.Returns(now);
        var consistent = new KekIntegrityReport(1, []);

        async Task<HealthStatus> StatusOf(OpsHealthSnapshot.Reading reading)
        {
            var snapshot = new OpsHealthSnapshot();
            snapshot.Publish(reading);
            return (await new OpsMonitorHealthCheck(snapshot, clock).CheckHealthAsync(new HealthCheckContext())).Status;
        }

        var intact = new HashChainVerification(true, 3, [], null, "h", null);
        Assert.AreEqual(HealthStatus.Healthy, await StatusOf(new(now, consistent, true, null, 0, KekIntegrityStatus.Ok, intact)));
        Assert.AreEqual(HealthStatus.Unhealthy, await StatusOf(new(now, consistent, true, null, 0, KekIntegrityStatus.Conflict, intact)));
        Assert.AreEqual(HealthStatus.Unhealthy, await StatusOf(new(now, consistent, true, null, 0, KekIntegrityStatus.Ok,
            new HashChainVerification(false, 1, [], 2, "h", "broken"))));
        Assert.AreEqual(HealthStatus.Degraded, await StatusOf(new(now, consistent, true, null, 0, KekIntegrityStatus.Ok,
            new HashChainVerification(true, 3, [4], null, "h", "damaged"))));
    }

    // ---- LOW: secrets in ToString ----------------------------------------------------------------------------------

    [TestMethod, TestCategory("Unit")]
    public void Totp_settings_never_print_their_secret()
    {
        const string Secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
        var settings = new TotpSettings(Secret, TotpAlgorithm.Sha256, 8, 30, "Example", "harry@example.com");

        Assert.IsFalse(settings.ToString().Contains(Secret, StringComparison.Ordinal));
        Assert.IsFalse($"{settings}".Contains(Secret, StringComparison.Ordinal));
        StringAssert.Contains(settings.ToString(), "[REDACTED]");
        StringAssert.Contains(settings.ToString(), "Example");
    }

    // ---- helpers ----------------------------------------------------------------------------------------------------

    private static BreakGlassRecord Record(string @event) =>
        new(DateTimeOffset.UnixEpoch, @event, Guid.NewGuid(), null, "Vault:1", Guid.NewGuid(), null, "why");

    private static string TempFile() => Path.Combine(Path.GetTempPath(), $"bg-{Path.GetRandomFileName()}.jsonl");

    private static ServiceProvider Provider(string connectionString, IKekProvider kek)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddKeyward(connectionString, _ => kek);
        return services.BuildServiceProvider();
    }

    private static async Task<bool> CanConnectAsync(ServiceProvider provider)
    {
        using var probe = provider.CreateScope();
        return await probe.ServiceProvider.GetRequiredService<KeywardDbContext>().Database.CanConnectAsync();
    }

    private static async Task SeedProjectAsync(ServiceProvider provider, Guid tenantId, Guid projectId)
    {
        using var scope = ScopeFor(provider, tenantId);
        var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
        db.Tenants.Add(new Tenant(tenantId, "system", isSystemTenant: true, DateTimeOffset.UtcNow));
        var project = new Project(projectId, tenantId, OwnerType.Tenant, tenantId, "review3", DateTimeOffset.UtcNow);
        project.AddEnvironment(Guid.NewGuid(), Am.Keyward.Core.Domain.ValueObjects.EnvironmentName.Production, DateTimeOffset.UtcNow);
        db.Projects.Add(project);
        await db.SaveChangesAsync();
    }

    private static async Task AppendAuditAsync(ServiceProvider provider, Guid tenantId, int count)
    {
        using var scope = ScopeFor(provider, tenantId);
        var audit = scope.ServiceProvider.GetRequiredService<IAuditSink>();
        var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
        for (var i = 0; i < count; i++)
        {
            await audit.AppendAsync(new AuditRequest(tenantId, AuditAction.Read, "Test", Guid.NewGuid(), null));
            await db.SaveChangesAsync();
        }
    }

    private static async Task<int> CanaryCountAsync(string connectionString)
    {
        await using var connection = new SqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM [amkeyward].[KekCanary]";
        return (int)(await command.ExecuteScalarAsync())!;
    }

    private static IServiceScope ScopeFor(ServiceProvider provider, Guid tenantId)
    {
        var scope = provider.CreateScope();
        scope.ServiceProvider.GetRequiredService<ITenantScopeSetter>().SetTenant(tenantId);
        scope.ServiceProvider.GetRequiredService<IActorScopeSetter>().SetSystemActor();
        return scope;
    }

    /// <summary>
    /// A database of its own, migrated and dropped again — for tests about the installation-wide canary, which a
    /// shared test database (and the tests running in parallel on it) would make non-deterministic.
    /// </summary>
    private sealed class IsolatedDatabase : IAsyncDisposable
    {
        private readonly string _name;
        private readonly string _master;

        private IsolatedDatabase(string connectionString, string name, string master)
        {
            ConnectionString = connectionString;
            _name = name;
            _master = master;
        }

        public string ConnectionString { get; }

        public static async Task<IsolatedDatabase?> CreateAsync()
        {
            var builder = new SqlConnectionStringBuilder(TestConfig.ConnectionString);
            var name = $"{builder.InitialCatalog}_{Guid.NewGuid():N}".ToLowerInvariant();
            var master = new SqlConnectionStringBuilder(TestConfig.ConnectionString) { InitialCatalog = "master" }.ConnectionString;
            builder.InitialCatalog = name;
            var database = new IsolatedDatabase(builder.ConnectionString, name, master);

            try
            {
                await using var provider = new ServiceCollection()
                    .AddKeyward(database.ConnectionString, RandomNumberGenerator.GetBytes(32), "migrator:v1")
                    .BuildServiceProvider();
                using var scope = provider.CreateScope();
                await scope.ServiceProvider.GetRequiredService<KeywardDbContext>().Database.MigrateAsync();
                return database;
            }
            catch (Exception ex) when (ex is SqlException or InvalidOperationException)
            {
                await database.DisposeAsync();
                return null;
            }
        }

        public async ValueTask DisposeAsync()
        {
            SqlConnection.ClearAllPools();
            try
            {
                await using var connection = new SqlConnection(_master);
                await connection.OpenAsync();
                await using var command = connection.CreateCommand();
                command.CommandText =
                    $"IF DB_ID(N'{_name}') IS NOT NULL BEGIN ALTER DATABASE [{_name}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [{_name}]; END";
                await command.ExecuteNonQueryAsync();
            }
            catch (SqlException)
            {
                // Best effort: a leftover test database is harmless and recognisable by its name.
            }
        }
    }
}

/// <summary>Key custody on Windows: the first run is exclusive, and the escrow import checks what it writes.</summary>
[TestClass]
[SupportedOSPlatform("windows")]
public class Review3KeyCustodyTests
{
    [TestMethod, TestCategory("Crypto")]
    public void Concurrent_first_starts_on_one_folder_end_up_with_one_key()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Inconclusive("DPAPI and NTFS access rules are Windows-only.");
            return;
        }

        var directory = Path.Combine(Path.GetTempPath(), "keyward-kek-race-" + Guid.NewGuid().ToString("N"));
        try
        {
            const int Starts = 8;
            using var go = new ManualResetEventSlim();
            var results = new (byte[] Key, string KekId, bool Created)[Starts];
            var threads = Enumerable.Range(0, Starts).Select(i => new Thread(() =>
            {
                go.Wait();
                results[i] = DpapiKekFile.LoadOrCreate(directory);
            })).ToList();
            threads.ForEach(t => t.Start());
            go.Set();
            threads.ForEach(t => t.Join());

            Assert.AreEqual(1, results.Count(r => r.Created), "Exactly one start creates the key.");
            Assert.AreEqual(1, results.Select(r => r.KekId).Distinct().Count(), "Every start holds the same key.");

            var (onDisk, onDiskId, created) = DpapiKekFile.LoadOrCreate(directory);
            Assert.IsFalse(created);
            Assert.AreEqual(results[0].KekId, onDiskId, "... and it is the key on disk, so it survives a restart.");
            CollectionAssert.AreEqual(results[0].Key, onDisk);
            Assert.HasCount(1, Directory.GetFiles(directory), "No temporary file is left behind.");
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [TestMethod, TestCategory("Crypto")]
    public void Creating_a_key_file_never_replaces_an_existing_one()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Inconclusive("DPAPI and NTFS access rules are Windows-only.");
            return;
        }

        var directory = Path.Combine(Path.GetTempPath(), "keyward-kek-exclusive-" + Guid.NewGuid().ToString("N"));
        try
        {
            var (key, _, _) = DpapiKekFile.LoadOrCreate(directory);
            var other = ProtectedData.Protect(RandomNumberGenerator.GetBytes(32), null, DataProtectionScope.LocalMachine);
            Assert.IsFalse(DpapiKekFile.TryCreateKeyFile(directory, other));
            CollectionAssert.AreEqual(key, DpapiKekFile.LoadOrCreate(directory).Key);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [TestMethod, TestCategory("Crypto")]
    public void Escrow_import_accepts_only_a_32_byte_key_and_prints_a_grant_for_the_app_identity()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Inconclusive("The escrow helper is Windows-only.");
            return;
        }

        DpapiKekEscrow.EnsureKekSize(new byte[32]);
        var refused = Assert.ThrowsExactly<InvalidOperationException>(() => DpapiKekEscrow.EnsureKekSize(new byte[16]));
        StringAssert.Contains(refused.Message, "16 bytes");

        // A wrapped 16-byte blob authenticates fine — only the size check stops it.
        var blob = DpapiKekEscrow.Wrap(new byte[16], "correct horse battery staple");
        Assert.HasCount(16, DpapiKekEscrow.Unwrap(blob, "correct horse battery staple"));

        Assert.AreEqual(
            @"icacls ""C:\ProgramData\Keyward\keys"" /grant ""IIS AppPool\Keyward:(OI)(CI)F"" /T",
            DpapiKekEscrow.IcaclsGrantLine(@"C:\ProgramData\Keyward\keys", @"IIS AppPool\Keyward"));
    }
}

internal static class HostServiceCollectionTestExtensions
{
    /// <summary>The startup check and the pollers need a database; host-start tests only look at option validation.</summary>
    public static void RemoveAllHostedServices(this IServiceCollection services)
    {
        foreach (var descriptor in services.Where(d => d.ServiceType == typeof(IHostedService)).ToList())
        {
            services.Remove(descriptor);
        }
    }
}
