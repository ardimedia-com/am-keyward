using Microsoft.Extensions.Logging;

namespace Am.Keyward.Infrastructure.Monitoring;

/// <summary>
/// Configuration for heartbeat monitoring (the token-silence dead-man's switch). Bound by the host from
/// <see cref="SectionName"/> (all values have safe defaults, so no configuration is required).
/// </summary>
public sealed class MonitoringOptions
{
    public const string SectionName = "Keyward:Monitoring";

    /// <summary>Kill-switch: disables the periodic monitor evaluation entirely.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>How often monitors are evaluated (seconds, floored at 10).</summary>
    public int CheckIntervalSeconds { get; set; } = 60;

    /// <summary>
    /// The time zone in which every monitor's watch window (weekdays, start/end times) is evaluated —
    /// one app-wide zone, deliberately not a per-monitor field. Windows or IANA id (e.g.
    /// "W. Europe Standard Time" or "Europe/Zurich"); empty = UTC. Timestamps stay UTC everywhere;
    /// only the wall-clock window interpretation uses this zone.
    /// </summary>
    public string? TimeZone { get; set; }

    /// <summary>Resolves <see cref="TimeZone"/>, falling back to UTC (logged by the caller once).</summary>
    public TimeZoneInfo ResolveTimeZone(ILogger? logger = null)
    {
        if (string.IsNullOrWhiteSpace(TimeZone))
        {
            return TimeZoneInfo.Utc;
        }

        try
        {
            return TimeZoneInfo.FindSystemTimeZoneById(TimeZone.Trim());
        }
        catch (Exception ex) when (ex is TimeZoneNotFoundException or InvalidTimeZoneException)
        {
            logger?.LogWarning(
                "Monitoring time zone '{TimeZone}' is unknown on this host — watch windows are evaluated in UTC instead.",
                TimeZone);
            return TimeZoneInfo.Utc;
        }
    }
}
