using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Domain.Software;
using Am.Keyward.Infrastructure.Statistics;

namespace Am.Keyward.Tests;

/// <summary>
/// The in-memory half of per-secret read statistics: recording must aggregate per (secret, environment)
/// — count, last read, last source — and draining must hand over the batch and start fresh, keeping the
/// secret-read hot path free of database work.
/// </summary>
[TestClass]
public class SecretReadAccumulatorTests
{
    private sealed class MutableClock : IClock
    {
        public DateTimeOffset UtcNow { get; set; } = new(2026, 8, 4, 12, 0, 0, TimeSpan.Zero);
    }

    [TestMethod, TestCategory("Unit")]
    public void Aggregates_count_last_read_and_source_per_secret_and_environment()
    {
        var clock = new MutableClock();
        var accumulator = new SecretReadAccumulator(clock);
        var tenant = Guid.NewGuid();
        var secret = Guid.NewGuid();
        var development = Guid.NewGuid();
        var production = Guid.NewGuid();

        accumulator.Record(tenant, secret, development, SecretReadSource.InProcess);
        clock.UtcNow = clock.UtcNow.AddMinutes(5);
        accumulator.Record(tenant, secret, development, SecretReadSource.Client);
        accumulator.Record(tenant, secret, production, SecretReadSource.Client);

        var batch = accumulator.Drain().ToDictionary(kv => kv.Key, kv => kv.Value);
        Assert.AreEqual(2, batch.Count); // one entry per (secret, environment)

        var dev = batch[(secret, development)];
        Assert.AreEqual(tenant, dev.TenantId);
        Assert.AreEqual(2, dev.Count);
        Assert.AreEqual(new DateTimeOffset(2026, 8, 4, 12, 5, 0, TimeSpan.Zero), dev.LastReadAt);
        Assert.AreEqual(SecretReadSource.Client, dev.LastSource); // the LAST source wins

        var prod = batch[(secret, production)];
        Assert.AreEqual(1, prod.Count);
        Assert.AreEqual(SecretReadSource.Client, prod.LastSource);
    }

    [TestMethod, TestCategory("Unit")]
    public void Drain_resets_the_batch_and_an_empty_batch_is_empty()
    {
        var accumulator = new SecretReadAccumulator(new MutableClock());
        accumulator.Record(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), SecretReadSource.InProcess);

        Assert.AreEqual(1, accumulator.Drain().Count);
        Assert.AreEqual(0, accumulator.Drain().Count); // drained → fresh batch
    }

    [TestMethod, TestCategory("Unit")]
    public void Record_read_on_the_entity_replaces_last_read_and_adds_the_count()
    {
        var access = new SecretReadAccess(
            Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(),
            new DateTimeOffset(2026, 8, 1, 8, 0, 0, TimeSpan.Zero), SecretReadSource.InProcess, 3);

        access.RecordRead(new DateTimeOffset(2026, 8, 4, 9, 30, 0, TimeSpan.Zero), SecretReadSource.Client, 5);

        Assert.AreEqual(new DateTimeOffset(2026, 8, 4, 9, 30, 0, TimeSpan.Zero), access.LastReadAt);
        Assert.AreEqual(SecretReadSource.Client, access.LastReadSource);
        Assert.AreEqual(8, access.ReadCount);
    }
}
