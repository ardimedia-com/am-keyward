using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Infrastructure.Monitoring;
using Microsoft.Extensions.Options;

namespace Am.Keyward.Infrastructure.Statistics;

/// <summary>
/// The in-memory half of token access statistics: <see cref="Record"/> is called on every authenticated
/// software-client request and only mutates a dictionary under a lock — no I/O, no exceptions escaping —
/// so the secret-read hot path never pays for statistics. <see cref="Drain"/> hands the accumulated batch
/// to the flush service and starts a fresh one. Singleton. Day buckets are keyed by the installation's
/// time zone (<see cref="MonitoringOptions.TimeZone"/>, server-local by default), so a day in the chart
/// is a calendar day as the operators experience it.
/// </summary>
public sealed class TokenAccessAccumulator(IClock clock, IOptions<MonitoringOptions> monitoringOptions) : ITokenAccessRecorder
{
    /// <summary>IPs longer than this are ignored (an IPv6 literal fits comfortably; anything longer is garbage).</summary>
    private const int MaxIpLength = 64;

    private readonly Lock gate = new();
    private readonly TimeZoneInfo zone = monitoringOptions.Value.ResolveTimeZone();
    private Dictionary<Guid, PendingTokenAccess> pending = [];

    public void Record(Guid tokenId, string? ipAddress)
    {
        var now = clock.UtcNow;
        var ip = Normalize(ipAddress);
        lock (gate)
        {
            if (!pending.TryGetValue(tokenId, out var access))
            {
                pending[tokenId] = access = new PendingTokenAccess(now);
            }

            access.Register(now, ip, zone);
        }
    }

    /// <summary>Takes the current batch (empty list when nothing was recorded) and resets the accumulator.</summary>
    public IReadOnlyList<KeyValuePair<Guid, PendingTokenAccess>> Drain()
    {
        Dictionary<Guid, PendingTokenAccess> drained;
        lock (gate)
        {
            if (pending.Count == 0)
            {
                return [];
            }

            drained = pending;
            pending = [];
        }

        return [.. drained];
    }

    private static string? Normalize(string? ipAddress)
    {
        var trimmed = ipAddress?.Trim();
        return string.IsNullOrEmpty(trimmed) || trimmed.Length > MaxIpLength ? null : trimmed;
    }
}

/// <summary>Everything recorded for one token since the last flush.</summary>
public sealed class PendingTokenAccess(DateTimeOffset firstAccessAt)
{
    private readonly Dictionary<DateOnly, long> countsByDay = [];
    private readonly Dictionary<string, DateTimeOffset> ipLastSeen = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>The first access in this batch — the silence-gap check compares it against the token's previous last access.</summary>
    public DateTimeOffset FirstAccessAt { get; } = firstAccessAt;

    public DateTimeOffset LastAccessAt { get; private set; } = firstAccessAt;

    public string? LastIp { get; private set; }

    public IReadOnlyDictionary<DateOnly, long> CountsByDay => countsByDay;

    public IReadOnlyDictionary<string, DateTimeOffset> IpLastSeen => ipLastSeen;

    public void Register(DateTimeOffset now, string? ip, TimeZoneInfo zone)
    {
        var day = DateOnly.FromDateTime(TimeZoneInfo.ConvertTime(now, zone).DateTime);
        countsByDay[day] = countsByDay.GetValueOrDefault(day) + 1;
        LastAccessAt = now;
        if (ip is not null)
        {
            ipLastSeen[ip] = now;
            LastIp = ip;
        }
    }
}
