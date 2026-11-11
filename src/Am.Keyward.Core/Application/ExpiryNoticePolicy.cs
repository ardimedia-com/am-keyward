namespace Am.Keyward.Core.Application;

/// <summary>
/// The notification schedule for credentials nearing expiry (app tokens, agent tokens, dated software-secret values):
/// a notice when the 30-, 20- and 10-day thresholds are crossed, then DAILY from 9 days down to the last day — and,
/// for advisory dates that keep working past the date (secret values), ONE notice once the date has passed. Pure
/// policy so the notification jobs and the tests share the exact same rules; the per-item dedupe state is the
/// item's <c>LastExpiryNoticeDaysLeft</c>.
/// </summary>
public static class ExpiryNoticePolicy
{
    /// <summary>How far ahead the schedule starts (used to pre-filter candidates).</summary>
    public const int WindowDays = 30;

    /// <summary>
    /// The value recorded as <c>LastExpiryNoticeDaysLeft</c> after the one «expired» notice (see
    /// <see cref="IsOverdueNoticeDue"/>). Never produced by <see cref="DaysLeft(DateTimeOffset, DateTimeOffset, TimeZoneInfo)"/>
    /// for a date still ahead, which is at least 1.
    /// </summary>
    public const int OverdueNoticeMarker = 0;

    private static readonly int[] CoarseThresholds = [30, 20, 10];

    /// <summary>
    /// Calendar days until <paramref name="expiresAt"/> as seen in <paramref name="zone"/> (the installation's time
    /// zone): the number of midnights between now and the expiry, at least 1 while it is still ahead (an expiry later
    /// today counts as 1, any time tomorrow as 1 too). Zero or negative once it has passed (0 = passed today,
    /// -1 = yesterday, …). Unlike a 24-hour ceiling, the count does not depend on the time of day.
    /// </summary>
    public static int DaysLeft(DateTimeOffset now, DateTimeOffset expiresAt, TimeZoneInfo zone)
    {
        ArgumentNullException.ThrowIfNull(zone);
        var today = DateOnly.FromDateTime(TimeZoneInfo.ConvertTime(now, zone).DateTime);
        var expiryDay = DateOnly.FromDateTime(TimeZoneInfo.ConvertTime(expiresAt, zone).DateTime);
        var days = expiryDay.DayNumber - today.DayNumber;
        return expiresAt > now ? Math.Max(days, 1) : Math.Min(days, 0);
    }

    /// <summary>Calendar days left, counted in UTC. Prefer the overload with the installation's time zone.</summary>
    public static int DaysLeft(DateTimeOffset now, DateTimeOffset expiresAt) => DaysLeft(now, expiresAt, TimeZoneInfo.Utc);

    /// <summary>
    /// Days left for an expiry given as a calendar DATE (valid through the end of <paramref name="expiresOn"/>):
    /// 1 on that day itself, 2 the day before, and 0 or less once it has passed.
    /// </summary>
    public static int DaysLeft(DateTimeOffset now, DateOnly expiresOn, TimeZoneInfo zone)
    {
        ArgumentNullException.ThrowIfNull(zone);
        var today = DateOnly.FromDateTime(TimeZoneInfo.ConvertTime(now, zone).DateTime);
        return expiresOn.DayNumber - today.DayNumber + 1;
    }

    /// <summary>
    /// True when a notice is due for this days-left value, given the last notice already sent for the item's
    /// current validity. A notice goes out when a threshold (30, 20, 10, then every day from 9) was CROSSED since the
    /// last notice — so a run that was missed on day 30 or 20 is caught up on the next run instead of skipping that
    /// bucket. Monotonic: nothing is repeated for a value at or above the last notified one. Expired (days left
    /// below 1) is never due here — see <see cref="IsOverdueNoticeDue"/>.
    /// </summary>
    public static bool IsDue(int daysLeft, int? lastNoticeDaysLeft)
    {
        if (daysLeft < 1 || daysLeft > WindowDays)
        {
            return false; // already expired, or still outside the window
        }

        if (lastNoticeDaysLeft is { } last && daysLeft >= last)
        {
            return false; // this bucket (or a closer one) was already announced
        }

        if (daysLeft <= 9)
        {
            return true; // daily phase
        }

        // The threshold whose bucket this day falls into (28 -> 30, 15 -> 20, 10 -> 10): due unless that bucket or a
        // closer one was already announced.
        var bucket = CoarseThresholds.Where(t => t >= daysLeft).Min();
        return lastNoticeDaysLeft is not { } announced || bucket < announced;
    }

    /// <summary>
    /// True when the one «expired» notice for an advisory date (a software-secret value's rotation date) is due: the
    /// date has passed and that notice was not sent yet for the current validity. Record
    /// <see cref="OverdueNoticeMarker"/> afterwards.
    /// </summary>
    public static bool IsOverdueNoticeDue(int daysLeft, int? lastNoticeDaysLeft) =>
        daysLeft < 1 && lastNoticeDaysLeft != OverdueNoticeMarker;
}
