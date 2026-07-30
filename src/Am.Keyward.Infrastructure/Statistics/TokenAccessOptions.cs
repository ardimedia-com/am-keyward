namespace Am.Keyward.Infrastructure.Statistics;

/// <summary>
/// Configuration for token access statistics and access-pattern alerts. Bound by the host from
/// <see cref="SectionName"/> (all values have safe defaults, so no configuration is required).
/// </summary>
public sealed class TokenAccessOptions
{
    public const string SectionName = "Keyward:TokenAccess";

    /// <summary>Kill-switch: disables recording, flushing and alert derivation entirely.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// How often the in-memory accumulator is persisted (seconds, floored at 5). Statistics and
    /// "last access" are accurate to this interval — the trade for keeping the secret-read hot path free
    /// of database writes.
    /// </summary>
    public int FlushIntervalSeconds { get; set; } = 60;

    /// <summary>
    /// How long daily counters, seen IPs and alerts are kept (days). An IP absent for the whole window
    /// ages out and counts as "new" again when it reappears.
    /// </summary>
    public int RetentionDays { get; set; } = 90;

    /// <summary>
    /// A token unused for at least this many days that is used again raises a
    /// <c>ResumedAfterSilence</c> alert.
    /// </summary>
    public int SilenceAlertDays { get; set; } = 30;
}
