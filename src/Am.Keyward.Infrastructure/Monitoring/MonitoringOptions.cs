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
    /// The installation's time zone — one app-wide zone, deliberately not a per-monitor field. It governs
    /// every server-side wall-clock interpretation: the monitors' watch windows (weekdays, start/end
    /// times), the statistics per-day aggregation buckets, and the timestamps rendered into notification
    /// e-mails (which have no browser to detect a viewer zone from). Windows or IANA id (e.g.
    /// "W. Europe Standard Time" or "Europe/Zurich"); empty = the server's local time zone.
    /// Timestamps are still STORED in UTC everywhere; this zone only shapes wall-clock interpretation.
    /// </summary>
    public string? TimeZone { get; set; }

    /// <summary>
    /// Resolves <see cref="TimeZone"/>, falling back to the server's local time zone (logged by the
    /// caller once when a configured zone is unknown).
    /// </summary>
    public TimeZoneInfo ResolveTimeZone(ILogger? logger = null)
    {
        if (string.IsNullOrWhiteSpace(TimeZone))
        {
            return TimeZoneInfo.Local;
        }

        try
        {
            return TimeZoneInfo.FindSystemTimeZoneById(TimeZone.Trim());
        }
        catch (Exception ex) when (ex is TimeZoneNotFoundException or InvalidTimeZoneException)
        {
            logger?.LogWarning(
                "Monitoring time zone '{TimeZone}' is unknown on this host — falling back to the server's local time zone.",
                TimeZone);
            return TimeZoneInfo.Local;
        }
    }
}
