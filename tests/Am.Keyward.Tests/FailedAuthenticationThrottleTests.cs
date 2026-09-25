using Am.Keyward.Api;

namespace Am.Keyward.Tests;

[TestClass]
public class FailedAuthenticationThrottleTests
{
    [TestMethod, TestCategory("Unit")]
    public void Ip_is_blocked_after_the_failure_limit_and_others_are_not()
    {
        using var throttle = new FailedAuthenticationThrottle(new KeywardSoftwareClientApiOptions
        {
            FailedAuthenticationLimit = 3,
            FailedAuthenticationWindow = TimeSpan.FromMinutes(5),
        });

        for (var i = 0; i < 2; i++)
        {
            throttle.RecordFailure("10.0.0.1");
        }
        Assert.IsFalse(throttle.IsBlocked("10.0.0.1"));

        throttle.RecordFailure("10.0.0.1");
        Assert.IsTrue(throttle.IsBlocked("10.0.0.1"));

        // Other callers are unaffected, including requests without a known address.
        Assert.IsFalse(throttle.IsBlocked("10.0.0.2"));
        Assert.IsFalse(throttle.IsBlocked(null));
    }

    [TestMethod, TestCategory("Unit")]
    public void Unseen_ip_is_not_blocked()
    {
        using var throttle = new FailedAuthenticationThrottle(new KeywardSoftwareClientApiOptions());
        Assert.IsFalse(throttle.IsBlocked("192.168.1.10"));
    }
}
