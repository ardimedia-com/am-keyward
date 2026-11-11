using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

namespace Am.Keyward.Api;

/// <summary>
/// Throttles the token LOOKUP of failing agent and app tokens — never a token that validates.
/// <para>
/// Failures are counted per (client address, presented token prefix). Once a pair has used up its allowance for the
/// window, further presentations of that prefix from that address are refused without a database lookup until the
/// window resets. A caller flooding junk tokens (random prefixes) from an address therefore never touches the
/// allowance of a genuine token presented from the same address — the shared lockout of the earlier per-address
/// design, where 20 junk headers blocked every valid token of an address (or, behind a proxy without forwarded
/// headers, of every caller), is gone.
/// </para>
/// <para>
/// A token that validated recently is remembered by an in-process fingerprint (HMAC-SHA-256 under a key that never
/// leaves the process — not the stored hash, not the token): it bypasses the throttle even when someone at the same
/// address hammers its prefix with wrong secrets, and the rate limiter gives it its own partition (see
/// <see cref="RateLimitPartitionKey"/>). The database lookup still runs on every request, so a revoked token stops
/// working at once.
/// </para>
/// <para>
/// <see cref="TryBegin"/> reserves the failure slot BEFORE the lookup and <see cref="Attempt.Succeeded"/> returns it,
/// so concurrent attempts cannot all pass a check that none of them has counted yet.
/// </para>
/// </summary>
public sealed class FailedAuthenticationThrottle : IDisposable
{
    /// <summary>How long a validated token keeps its fingerprint (refreshed on every success).</summary>
    public static readonly TimeSpan KnownGoodLifetime = TimeSpan.FromHours(1);

    private const int MaxEntries = 10_000;

    private readonly int failedAttemptLimit;
    private readonly TimeSpan window;
    private readonly TimeProvider time;
    private readonly byte[] fingerprintKey = RandomNumberGenerator.GetBytes(32);
    private readonly ConcurrentDictionary<string, Counter> failures = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, DateTimeOffset> knownGood = new(StringComparer.Ordinal);

    public FailedAuthenticationThrottle(KeywardSoftwareClientApiOptions options)
        : this(options.FailedAuthenticationLimit, options.FailedAuthenticationWindow)
    {
    }

    /// <summary>
    /// One throttle is shared by every Keyward token scheme (software clients, agents).
    /// </summary>
    public FailedAuthenticationThrottle(int failedAttemptLimit, TimeSpan window, TimeProvider? timeProvider = null)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(failedAttemptLimit, 1);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(window, TimeSpan.Zero);

        this.failedAttemptLimit = failedAttemptLimit;
        this.window = window;
        time = timeProvider ?? TimeProvider.System;
    }

    /// <summary>
    /// Starts one authentication attempt of <paramref name="presentedToken"/> from <paramref name="clientIp"/>. Returns
    /// null when the (address, prefix) pair has used up its failures and the token has not validated recently — refuse
    /// it then without a lookup. Otherwise the attempt holds a failure slot until it is completed.
    /// </summary>
    public Attempt? TryBegin(string? clientIp, string presentedToken)
    {
        var fingerprint = Fingerprint(presentedToken);
        var key = $"{clientIp ?? "unknown"}|{Prefix(presentedToken)}";
        var now = time.GetUtcNow();
        Prune(now);

        if (IsKnownGood(fingerprint, now))
        {
            return new Attempt(this, fingerprint, counter: null, windowStart: default);
        }

        var counter = failures.GetOrAdd(key, _ => new Counter());
        lock (counter)
        {
            if (now - counter.WindowStart >= window)
            {
                counter.WindowStart = now;
                counter.Count = 0;
                counter.Failures = 0;
            }

            if (counter.Count >= failedAttemptLimit)
            {
                return null;
            }

            counter.Count++;
            return new Attempt(this, fingerprint, counter, counter.WindowStart);
        }
    }

    /// <summary>
    /// The rate-limiter partition of a request: a recently validated token gets its own partition; everything else —
    /// unknown tokens, junk, anonymous requests — shares one partition per client address, so junk headers can neither
    /// open fresh partitions to bypass the limit nor inflate the limiter's memory.
    /// </summary>
    public string RateLimitPartitionKey(string? authorizationHeader, string? clientIp)
    {
        var token = BearerToken(authorizationHeader);
        if (token is not null)
        {
            var fingerprint = Fingerprint(token);
            if (IsKnownGood(fingerprint, time.GetUtcNow()))
            {
                return "tok:" + fingerprint;
            }
        }

        return "ip:" + (clientIp ?? "unknown");
    }

    /// <summary>The token of a <c>Bearer</c> authorization header, or null.</summary>
    public static string? BearerToken(string? authorizationHeader)
    {
        const string bearer = "Bearer ";
        return authorizationHeader is not null && authorizationHeader.StartsWith(bearer, StringComparison.OrdinalIgnoreCase)
            ? authorizationHeader[bearer.Length..].Trim()
            : null;
    }

    public void Dispose()
    {
        failures.Clear();
        knownGood.Clear();
    }

    // The non-secret lookup handle of a Keyward token (scheme_prefix_secret); empty for anything else.
    private static string Prefix(string token)
    {
        var parts = token.Split('_');
        return parts.Length == 3 ? parts[1] : string.Empty;
    }

    private string Fingerprint(string token) =>
        Convert.ToHexString(HMACSHA256.HashData(fingerprintKey, Encoding.UTF8.GetBytes(token)));

    private bool IsKnownGood(string fingerprint, DateTimeOffset now) =>
        knownGood.TryGetValue(fingerprint, out var until) && until > now;

    // Returns, for a failure, whether it used up the pair's allowance (for a one-time warning).
    private bool Complete(string fingerprint, Counter? counter, DateTimeOffset windowStart, Outcome outcome)
    {
        if (outcome == Outcome.Succeeded)
        {
            knownGood[fingerprint] = time.GetUtcNow() + KnownGoodLifetime;
        }

        if (counter is null)
        {
            return false;
        }

        lock (counter)
        {
            var sameWindow = counter.WindowStart == windowStart;
            if (outcome == Outcome.Failed)
            {
                // Count holds in-flight reservations too; Failures only the decided ones, so exactly one failure trips.
                return sameWindow && ++counter.Failures == failedAttemptLimit;
            }

            // Return the slot only within the window it was taken from.
            if (sameWindow && counter.Count > 0)
            {
                counter.Count--;
            }

            return false;
        }
    }

    // Bounded memory: once a table grows past the cap, expired entries are dropped.
    private void Prune(DateTimeOffset now)
    {
        if (failures.Count > MaxEntries)
        {
            foreach (var entry in failures)
            {
                bool expired;
                lock (entry.Value)
                {
                    expired = now - entry.Value.WindowStart >= window;
                }

                if (expired)
                {
                    failures.TryRemove(entry.Key, out _);
                }
            }
        }

        if (knownGood.Count > MaxEntries)
        {
            foreach (var entry in knownGood.Where(e => e.Value <= now).ToList())
            {
                knownGood.TryRemove(entry.Key, out _);
            }
        }
    }

    private enum Outcome
    {
        Succeeded,
        Failed,
        Abandoned,
    }

    internal sealed class Counter
    {
        public DateTimeOffset WindowStart;
        public int Count;
        public int Failures;
    }

    /// <summary>One authentication attempt; complete it exactly once with the lookup's result.</summary>
    public sealed class Attempt
    {
        private readonly FailedAuthenticationThrottle owner;
        private readonly string fingerprint;
        private readonly Counter? counter;
        private readonly DateTimeOffset windowStart;
        private int completed;

        internal Attempt(FailedAuthenticationThrottle owner, string fingerprint, Counter? counter, DateTimeOffset windowStart)
        {
            this.owner = owner;
            this.fingerprint = fingerprint;
            this.counter = counter;
            this.windowStart = windowStart;
        }

        /// <summary>The token validated: its slot is returned and it bypasses the throttle from now on.</summary>
        public void Succeeded() => Complete(Outcome.Succeeded);

        /// <summary>
        /// The token was refused: the slot stays counted against its (address, prefix). Returns true when this failure
        /// used up the pair's allowance, so the caller can log the block once.
        /// </summary>
        public bool Failed() => Complete(Outcome.Failed);

        /// <summary>The lookup could not decide (e.g. the database is unreachable): the slot is returned, nothing is remembered.</summary>
        public void Abandoned() => Complete(Outcome.Abandoned);

        private bool Complete(Outcome outcome) =>
            Interlocked.Exchange(ref completed, 1) == 0 && owner.Complete(fingerprint, counter, windowStart, outcome);
    }
}
