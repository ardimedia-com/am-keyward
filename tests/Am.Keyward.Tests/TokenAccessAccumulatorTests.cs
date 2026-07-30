using Am.Keyward.Core.Abstractions;
using Am.Keyward.Infrastructure.Statistics;

namespace Am.Keyward.Tests;

/// <summary>
/// The in-memory half of token access statistics: recording must aggregate per token (daily counts, seen
/// IPs, last access) and draining must hand over the batch and start fresh — this is what keeps the
/// secret-read hot path free of database work.
/// </summary>
[TestClass]
public class TokenAccessAccumulatorTests
{
    private sealed class MutableClock : IClock
    {
        public DateTimeOffset UtcNow { get; set; } = new(2026, 7, 30, 12, 0, 0, TimeSpan.Zero);
    }

    [TestMethod, TestCategory("Unit")]
    public void Aggregates_counts_ips_and_last_access_per_token()
    {
        var clock = new MutableClock();
        var accumulator = new TokenAccessAccumulator(clock);
        var tokenA = Guid.NewGuid();
        var tokenB = Guid.NewGuid();

        accumulator.Record(tokenA, "10.0.0.1");
        clock.UtcNow = clock.UtcNow.AddMinutes(5);
        accumulator.Record(tokenA, "10.0.0.2");
        accumulator.Record(tokenB, null);

        var batch = accumulator.Drain().ToDictionary(kv => kv.Key, kv => kv.Value);
        Assert.AreEqual(2, batch.Count);

        var a = batch[tokenA];
        Assert.AreEqual(2, a.CountsByDay[new DateOnly(2026, 7, 30)]);
        Assert.AreEqual(2, a.IpLastSeen.Count);
        Assert.AreEqual("10.0.0.2", a.LastIp);
        Assert.AreEqual(new DateTimeOffset(2026, 7, 30, 12, 0, 0, TimeSpan.Zero), a.FirstAccessAt);
        Assert.AreEqual(new DateTimeOffset(2026, 7, 30, 12, 5, 0, TimeSpan.Zero), a.LastAccessAt);

        var b = batch[tokenB];
        Assert.AreEqual(1, b.CountsByDay[new DateOnly(2026, 7, 30)]);
        Assert.AreEqual(0, b.IpLastSeen.Count);
        Assert.IsNull(b.LastIp);
    }

    [TestMethod, TestCategory("Unit")]
    public void Counts_split_on_the_utc_day_boundary()
    {
        var clock = new MutableClock { UtcNow = new DateTimeOffset(2026, 7, 30, 23, 59, 0, TimeSpan.Zero) };
        var accumulator = new TokenAccessAccumulator(clock);
        var token = Guid.NewGuid();

        accumulator.Record(token, "10.0.0.1");
        clock.UtcNow = clock.UtcNow.AddMinutes(2); // 00:01 next day
        accumulator.Record(token, "10.0.0.1");

        var access = accumulator.Drain().Single(kv => kv.Key == token).Value;
        Assert.AreEqual(1, access.CountsByDay[new DateOnly(2026, 7, 30)]);
        Assert.AreEqual(1, access.CountsByDay[new DateOnly(2026, 7, 31)]);
    }

    [TestMethod, TestCategory("Unit")]
    public void Drain_resets_the_batch_and_an_empty_batch_is_empty()
    {
        var accumulator = new TokenAccessAccumulator(new MutableClock());
        accumulator.Record(Guid.NewGuid(), "10.0.0.1");

        Assert.AreEqual(1, accumulator.Drain().Count);
        Assert.AreEqual(0, accumulator.Drain().Count); // drained → fresh batch
    }

    [TestMethod, TestCategory("Unit")]
    public void Ip_is_normalized_and_garbage_is_dropped()
    {
        var accumulator = new TokenAccessAccumulator(new MutableClock());
        var token = Guid.NewGuid();

        accumulator.Record(token, "  10.0.0.1  ");            // trimmed
        accumulator.Record(token, new string('x', 200));       // overlong → treated as no IP
        accumulator.Record(token, "   ");                      // blank → no IP

        var access = accumulator.Drain().Single(kv => kv.Key == token).Value;
        Assert.AreEqual(1, access.IpLastSeen.Count);
        Assert.AreEqual("10.0.0.1", access.IpLastSeen.Keys.Single());
        Assert.AreEqual(3, access.CountsByDay.Values.Sum()); // every request counts, with or without IP
    }

    [TestMethod, TestCategory("Unit")]
    public void Ip_matching_is_case_insensitive_for_ipv6_literals()
    {
        var accumulator = new TokenAccessAccumulator(new MutableClock());
        var token = Guid.NewGuid();

        accumulator.Record(token, "2001:db8::AB");
        accumulator.Record(token, "2001:DB8::ab");

        var access = accumulator.Drain().Single(kv => kv.Key == token).Value;
        Assert.AreEqual(1, access.IpLastSeen.Count);
    }

    [TestMethod, TestCategory("Unit")]
    public void Token_last_access_is_recorded_and_keeps_the_previous_ip_when_none_is_seen()
    {
        var token = Core.Domain.Software.SoftwareClientToken.CreatePending(
            Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), "app-prod", null,
            new DateTimeOffset(2026, 7, 1, 0, 0, 0, TimeSpan.Zero));

        token.RecordAccess(new DateTimeOffset(2026, 7, 30, 12, 0, 0, TimeSpan.Zero), "10.0.0.1");
        token.RecordAccess(new DateTimeOffset(2026, 7, 30, 13, 0, 0, TimeSpan.Zero), null);

        Assert.AreEqual(new DateTimeOffset(2026, 7, 30, 13, 0, 0, TimeSpan.Zero), token.LastAccessAt);
        Assert.AreEqual("10.0.0.1", token.LastAccessIp); // an access without a resolvable IP keeps the last known one
    }
}
