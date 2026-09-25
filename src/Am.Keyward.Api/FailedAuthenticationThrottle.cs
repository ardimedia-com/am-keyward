using System.Threading.RateLimiting;

namespace Am.Keyward.Api;

/// <summary>
/// Throttles failed token authentications per client IP. The per-token rate limiter cannot do this: its
/// partition key is the presented token, so every guessed token opens a fresh window. Here each FAILED
/// attempt consumes a permit of the caller's IP; once the IP's window is exhausted, further attempts from it
/// are refused without a database lookup until the window resets.
/// </summary>
/// <remarks>
/// Deliberately keyed by IP, not by token prefix: the prefix is visible in the token list, so a per-prefix
/// lock would let anyone who knows it lock the legitimate client out. Behind a proxy the IP is only
/// meaningful when the host configures forwarded headers (with known proxies).
/// </remarks>
public sealed class FailedAuthenticationThrottle : IDisposable
{
    private readonly PartitionedRateLimiter<string> limiter;

    public FailedAuthenticationThrottle(KeywardSoftwareClientApiOptions options)
        : this(options.FailedAuthenticationLimit, options.FailedAuthenticationWindow)
    {
    }

    /// <summary>
    /// One throttle is shared by every Keyward token scheme (software clients, agents): a caller guessing tokens
    /// of either kind uses up the same allowance.
    /// </summary>
    public FailedAuthenticationThrottle(int failedAttemptLimit, TimeSpan window)
    {
        limiter = PartitionedRateLimiter.Create<string, string>(ip =>
            RateLimitPartition.GetFixedWindowLimiter(ip, _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = failedAttemptLimit,
                Window = window,
                QueueLimit = 0,
            }));
    }

    /// <summary>Whether the IP has used up its failed attempts for the current window.</summary>
    public bool IsBlocked(string? ip) =>
        limiter.GetStatistics(Key(ip)) is { CurrentAvailablePermits: <= 0 };

    /// <summary>Counts one failed authentication against the IP.</summary>
    public void RecordFailure(string? ip)
    {
        using var lease = limiter.AttemptAcquire(Key(ip));
    }

    public void Dispose() => limiter.Dispose();

    private static string Key(string? ip) => ip ?? "unknown";
}
