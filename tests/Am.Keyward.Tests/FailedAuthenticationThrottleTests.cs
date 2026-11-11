using Am.Keyward.Api;

namespace Am.Keyward.Tests;

[TestClass]
public class FailedAuthenticationThrottleTests
{
    private const string Valid = "amkw_aaaaaaaaaaaa_0000000000000000000000000000000000000000000000000000000000000001";

    [TestMethod, TestCategory("Unit")]
    public void A_prefix_is_blocked_after_the_failure_limit_from_that_address_only()
    {
        using var throttle = new FailedAuthenticationThrottle(3, TimeSpan.FromMinutes(5));
        const string guess = "amkw_bbbbbbbbbbbb_ffff";

        for (var i = 0; i < 3; i++)
        {
            throttle.TryBegin("10.0.0.1", guess + i)!.Failed();
        }

        Assert.IsNull(throttle.TryBegin("10.0.0.1", guess + "x"), "the prefix is used up from this address");
        Assert.IsNotNull(throttle.TryBegin("10.0.0.2", guess + "x"), "another address keeps its own allowance");
        Assert.IsNotNull(throttle.TryBegin("10.0.0.1", Valid), "another prefix from the same address is unaffected");
    }

    [TestMethod, TestCategory("Unit")]
    public void Junk_with_random_prefixes_never_blocks_a_valid_token_from_the_same_address()
    {
        using var throttle = new FailedAuthenticationThrottle(2, TimeSpan.FromMinutes(5));

        for (var i = 0; i < 50; i++)
        {
            throttle.TryBegin("10.0.0.1", $"amkw_{i:x12}_junk")?.Failed();
        }

        var attempt = throttle.TryBegin("10.0.0.1", Valid);
        Assert.IsNotNull(attempt);
        attempt.Succeeded();
    }

    [TestMethod, TestCategory("Unit")]
    public void A_token_that_validated_bypasses_a_used_up_prefix()
    {
        using var throttle = new FailedAuthenticationThrottle(2, TimeSpan.FromMinutes(5));
        throttle.TryBegin("10.0.0.1", Valid)!.Succeeded();

        // Someone at the same address hammers the same prefix with wrong secrets.
        for (var i = 0; i < 5; i++)
        {
            throttle.TryBegin("10.0.0.1", "amkw_aaaaaaaaaaaa_wrong" + i)?.Failed();
        }

        Assert.IsNull(throttle.TryBegin("10.0.0.1", "amkw_aaaaaaaaaaaa_wrong-again"));
        Assert.IsNotNull(throttle.TryBegin("10.0.0.1", Valid), "the genuine token is never refused by the throttle");
    }

    [TestMethod, TestCategory("Unit")]
    public void Concurrent_attempts_cannot_exceed_the_limit_and_success_or_abandon_returns_the_slot()
    {
        using var throttle = new FailedAuthenticationThrottle(2, TimeSpan.FromMinutes(5));
        const string token = "amkw_cccccccccccc_x";

        // Two attempts in flight hold both slots before either has completed: a third is refused at once.
        var first = throttle.TryBegin("10.0.0.1", token);
        var second = throttle.TryBegin("10.0.0.1", token);
        Assert.IsNotNull(first);
        Assert.IsNotNull(second);
        Assert.IsNull(throttle.TryBegin("10.0.0.1", token));

        // A lookup that could not decide (database down) returns its slot.
        second.Abandoned();
        var third = throttle.TryBegin("10.0.0.1", token);
        Assert.IsNotNull(third);

        Assert.IsFalse(first.Failed(), "one failure is not yet the limit");
        Assert.IsTrue(third.Failed(), "the second failure uses the allowance up");
        Assert.IsNull(throttle.TryBegin("10.0.0.1", token));
    }

    [TestMethod, TestCategory("Unit")]
    public void The_window_resets_the_allowance()
    {
        var time = new ManualTime(DateTimeOffset.UnixEpoch);
        using var throttle = new FailedAuthenticationThrottle(1, TimeSpan.FromMinutes(5), time);
        const string token = "amkw_dddddddddddd_x";

        throttle.TryBegin("10.0.0.1", token)!.Failed();
        Assert.IsNull(throttle.TryBegin("10.0.0.1", token));

        time.Now += TimeSpan.FromMinutes(5);
        Assert.IsNotNull(throttle.TryBegin("10.0.0.1", token));
    }

    [TestMethod, TestCategory("Unit")]
    public void Rate_limit_partitions_give_validated_tokens_their_own_and_junk_the_address()
    {
        using var throttle = new FailedAuthenticationThrottle(5, TimeSpan.FromMinutes(5));

        var junkA = throttle.RateLimitPartitionKey("Bearer amkw_000000000001_a", "10.0.0.1");
        var junkB = throttle.RateLimitPartitionKey("Bearer amkw_000000000002_b", "10.0.0.1");
        var anonymous = throttle.RateLimitPartitionKey(null, "10.0.0.1");
        Assert.AreEqual(junkA, junkB, "junk headers share the address's partition — no fresh partition per header");
        Assert.AreEqual(junkA, anonymous);

        throttle.TryBegin("10.0.0.1", Valid)!.Succeeded();
        var valid = throttle.RateLimitPartitionKey("Bearer " + Valid, "10.0.0.1");
        Assert.AreNotEqual(junkA, valid, "a validated token is not limited by the junk of its address");
        Assert.DoesNotContain(Valid, valid, "the partition key never carries the token");
    }

    private sealed class ManualTime(DateTimeOffset start) : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = start;

        public override DateTimeOffset GetUtcNow() => Now;
    }
}
