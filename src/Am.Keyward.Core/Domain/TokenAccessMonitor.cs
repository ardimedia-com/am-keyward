namespace Am.Keyward.Core.Domain.Software;

/// <summary>The monitor's last evaluated heartbeat state.</summary>
public enum TokenMonitorState
{
    /// <summary>The token accessed its secrets within the allowed silence.</summary>
    Up = 0,

    /// <summary>The allowed silence was exceeded — the consumer looks dead (dead-man's switch fired).</summary>
    Down = 1,
}

/// <summary>
/// Heartbeat monitoring ("dead-man's switch") for one software-client token. A consumer that reads its
/// secrets at run start leaves an implicit heartbeat (<see cref="SoftwareClientToken.LastAccessAt"/>);
/// this monitor alarms when that heartbeat stays out longer than <see cref="MaxSilenceMinutes"/> — the
/// case an app cannot report itself: a process that never started sends no mail. Evaluated periodically
/// by the monitoring background service; transitions append <see cref="TokenAccessAlert"/> rows
/// (<see cref="TokenAccessAlertKind.HeartbeatMissed"/> / <see cref="TokenAccessAlertKind.HeartbeatRecovered"/>),
/// which the statistics UI shows and the opt-in alert mail delivers. Like the other statistics tables the
/// monitor is installation-global (no tenant query filter / row-level security); reads always scope
/// through the token's (tenant, project).
/// </summary>
public sealed class TokenAccessMonitor
{
    /// <summary>Watch-days bitmask covering all seven days (bit 0 = Monday … bit 6 = Sunday).</summary>
    public const byte AllDays = 0x7F;

    public Guid Id { get; private set; }
    public Guid TenantId { get; private set; }
    public Guid TokenId { get; private set; }
    public bool Enabled { get; private set; }

    /// <summary>How long the token may stay silent (counted inside the watch window) before the monitor goes down.</summary>
    public int MaxSilenceMinutes { get; private set; }

    /// <summary>Days on which silence counts, as a bitmask (bit 0 = Monday … bit 6 = Sunday).</summary>
    public byte WatchDaysMask { get; private set; }

    /// <summary>Start of the daily watch window (wall clock in the app-wide monitoring time zone); null = whole day.</summary>
    public TimeOnly? WatchStart { get; private set; }

    /// <summary>End of the daily watch window; null = whole day. Start after end spans midnight.</summary>
    public TimeOnly? WatchEnd { get; private set; }

    /// <summary>Send an all-clear mail when the heartbeat returns after a down transition.</summary>
    public bool NotifyOnRecovery { get; private set; }

    /// <summary>Evaluation pauses until this instant (maintenance windows) and resumes by itself.</summary>
    public DateTimeOffset? SnoozeUntil { get; private set; }

    public TokenMonitorState State { get; private set; }
    public DateTimeOffset? LastStateChangeAt { get; private set; }

    /// <summary>Diagnostic: when the background service last evaluated this monitor (written throttled).</summary>
    public DateTimeOffset? LastEvaluatedAt { get; private set; }

    /// <summary>Also the silence reference for a token that has never been accessed.</summary>
    public DateTimeOffset CreatedAt { get; private set; }

    public TokenAccessMonitor(
        Guid id,
        Guid tenantId,
        Guid tokenId,
        int maxSilenceMinutes,
        byte watchDaysMask,
        TimeOnly? watchStart,
        TimeOnly? watchEnd,
        bool notifyOnRecovery,
        DateTimeOffset createdAt)
    {
        Id = id;
        TenantId = tenantId;
        TokenId = tokenId;
        Enabled = true;
        NotifyOnRecovery = notifyOnRecovery;
        State = TokenMonitorState.Up;
        CreatedAt = createdAt;
        SetSchedule(maxSilenceMinutes, watchDaysMask, watchStart, watchEnd);
    }

    public void SetEnabled(bool enabled) => Enabled = enabled;

    public void SetNotifyOnRecovery(bool enabled) => NotifyOnRecovery = enabled;

    public void SetSchedule(int maxSilenceMinutes, byte watchDaysMask, TimeOnly? watchStart, TimeOnly? watchEnd)
    {
        if (maxSilenceMinutes < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(maxSilenceMinutes), "The allowed silence must be at least one minute.");
        }

        if (watchDaysMask == 0 || watchDaysMask > AllDays)
        {
            throw new ArgumentOutOfRangeException(nameof(watchDaysMask), "The watch window needs at least one weekday.");
        }

        if (watchStart.HasValue != watchEnd.HasValue)
        {
            throw new ArgumentException("The watch window needs both a start and an end time (or neither).", nameof(watchEnd));
        }

        if (watchStart.HasValue && watchStart.Value == watchEnd!.Value)
        {
            throw new ArgumentException("The watch window must not be empty (start equals end).", nameof(watchEnd));
        }

        MaxSilenceMinutes = maxSilenceMinutes;
        WatchDaysMask = watchDaysMask;
        WatchStart = watchStart;
        WatchEnd = watchEnd;
    }

    public void Snooze(DateTimeOffset until) => SnoozeUntil = until;

    public void ClearSnooze() => SnoozeUntil = null;

    public void MarkEvaluated(DateTimeOffset at) => LastEvaluatedAt = at;

    /// <summary>Applies an evaluated state; returns true when this was a transition (worth an alert).</summary>
    public bool ApplyState(TokenMonitorState state, DateTimeOffset at)
    {
        if (State == state)
        {
            return false;
        }

        State = state;
        LastStateChangeAt = at;
        return true;
    }
}

/// <summary>
/// The watch-window calendar math behind <see cref="TokenAccessMonitor"/>: how much time inside the
/// configured weekday/time-of-day window has passed between two instants, and when a silence deadline
/// falls. Silence is counted only while the window is open, so a Monday-to-Friday job does not false-alarm
/// over its scheduled weekend pause. All window times are wall clock in the given zone (they follow the
/// operator's local time including DST; on a DST transition day the elapsed window time can be off by the
/// shifted hour — irrelevant at the granularity of job monitoring).
/// </summary>
public static class WatchWindowCalculator
{
    private const int MaxProjectionDays = 730;

    /// <summary>Wall-clock time between <paramref name="from"/> and <paramref name="to"/> that falls inside the window.</summary>
    public static TimeSpan ElapsedInWindow(
        DateTimeOffset from, DateTimeOffset to, byte watchDaysMask, TimeOnly? watchStart, TimeOnly? watchEnd, TimeZoneInfo zone)
    {
        if (to <= from)
        {
            return TimeSpan.Zero;
        }

        if (watchDaysMask >= TokenAccessMonitor.AllDays && watchStart is null)
        {
            return to - from; // always-open window: plain difference, no calendar walk
        }

        var localFrom = TimeZoneInfo.ConvertTime(from, zone).DateTime;
        var localTo = TimeZoneInfo.ConvertTime(to, zone).DateTime;

        var elapsed = TimeSpan.Zero;
        for (var day = localFrom.Date; day <= localTo.Date; day = day.AddDays(1))
        {
            foreach (var (segmentStart, segmentEnd) in SegmentsOf(day, watchDaysMask, watchStart, watchEnd))
            {
                var overlapStart = segmentStart < localFrom ? localFrom : segmentStart;
                var overlapEnd = segmentEnd > localTo ? localTo : segmentEnd;
                if (overlapEnd > overlapStart)
                {
                    elapsed += overlapEnd - overlapStart;
                }
            }
        }

        return elapsed;
    }

    /// <summary>
    /// The instant at which the in-window silence since <paramref name="reference"/> reaches
    /// <paramref name="maxSilence"/> — the "next deadline" the UI shows. Null when the window never
    /// accumulates that much time within the projection horizon.
    /// </summary>
    public static DateTimeOffset? NextDeadline(
        DateTimeOffset reference, TimeSpan maxSilence, byte watchDaysMask, TimeOnly? watchStart, TimeOnly? watchEnd, TimeZoneInfo zone)
    {
        if (watchDaysMask >= TokenAccessMonitor.AllDays && watchStart is null)
        {
            return reference + maxSilence;
        }

        var local = TimeZoneInfo.ConvertTime(reference, zone);
        var localReference = local.DateTime;
        var remaining = maxSilence;

        for (var day = localReference.Date; day <= localReference.Date.AddDays(MaxProjectionDays); day = day.AddDays(1))
        {
            foreach (var (segmentStart, segmentEnd) in SegmentsOf(day, watchDaysMask, watchStart, watchEnd))
            {
                var effectiveStart = segmentStart < localReference ? localReference : segmentStart;
                if (segmentEnd <= effectiveStart)
                {
                    continue;
                }

                var segmentLength = segmentEnd - effectiveStart;
                if (segmentLength >= remaining)
                {
                    var localDeadline = effectiveStart + remaining;
                    return new DateTimeOffset(localDeadline, zone.GetUtcOffset(localDeadline));
                }

                remaining -= segmentLength;
            }
        }

        return null;
    }

    /// <summary>Open window segments of one local calendar day; an overnight window contributes two.</summary>
    private static IEnumerable<(DateTime Start, DateTime End)> SegmentsOf(
        DateTime day, byte watchDaysMask, TimeOnly? watchStart, TimeOnly? watchEnd)
    {
        if (!IsWatchedDay(day.DayOfWeek, watchDaysMask))
        {
            yield break;
        }

        if (watchStart is not { } start || watchEnd is not { } end)
        {
            yield return (day, day.AddDays(1));
            yield break;
        }

        if (start < end)
        {
            yield return (day + start.ToTimeSpan(), day + end.ToTimeSpan());
            yield break;
        }

        // Overnight window (e.g. 22:00–06:00): the early segment belongs to this day's date, the late
        // segment runs to midnight. Both are gated on THIS day being watched.
        yield return (day, day + end.ToTimeSpan());
        yield return (day + start.ToTimeSpan(), day.AddDays(1));
    }

    /// <summary>Bit 0 = Monday … bit 6 = Sunday (ISO week order).</summary>
    public static bool IsWatchedDay(DayOfWeek day, byte watchDaysMask) =>
        (watchDaysMask & (1 << (((int)day + 6) % 7))) != 0;
}
