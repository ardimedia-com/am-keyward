using Am.Keyward.Infrastructure.Statistics;

namespace Am.Keyward.Infrastructure.Monitoring;

/// <summary>
/// How fine a heartbeat monitor can resolve silence. An access becomes visible to the evaluator after at most one flush
/// interval (persisted <c>LastAccessAt</c>; the in-memory accumulator is consulted too, but not after a restart) and is
/// looked at once per check interval. A monitor whose allowed silence is shorter than both together reports Down
/// although the heartbeat arrived on time — so the allowed silence has a floor.
/// </summary>
public static class HeartbeatTiming
{
    /// <summary>
    /// The smallest allowed silence, in whole minutes: check interval + flush interval, rounded up, plus one minute of
    /// margin.
    /// </summary>
    public static int MinimumMaxSilenceMinutes(MonitoringOptions monitoring, TokenAccessOptions tokenAccess)
    {
        ArgumentNullException.ThrowIfNull(monitoring);
        ArgumentNullException.ThrowIfNull(tokenAccess);
        var seconds = Math.Max(monitoring.CheckIntervalSeconds, 10) + Math.Max(tokenAccess.FlushIntervalSeconds, 5);
        return (int)Math.Ceiling(seconds / 60d) + 1;
    }
}
