namespace Am.Keyward.Core.Application;

/// <summary>
/// The notification schedule for app tokens nearing expiry: a notice at 30, 20 and 10 days before expiry,
/// then DAILY from 9 days down to the last day. Pure policy so the host's mail job and the tests share the
/// exact same rules; the per-token dedupe state is <c>SoftwareClientToken.LastExpiryNoticeDaysLeft</c>.
/// </summary>
public static class TokenExpiryNoticePolicy
{
    /// <summary>How far ahead the schedule starts (used to pre-filter candidate tokens).</summary>
    public const int WindowDays = 30;

    /// <summary>Whole days until expiry, rounded up (an expiry later today counts as 1).</summary>
    public static int DaysLeft(DateTimeOffset now, DateTimeOffset expiresAt) =>
        (int)Math.Ceiling((expiresAt - now).TotalDays);

    /// <summary>
    /// True when a notice is due for this days-left value, given the last notice already sent for the
    /// token's current validity window. Monotonic: a notice is only sent when days-left has moved BELOW
    /// the last notified value, so clock jitter or frequent runs never repeat a notice.
    /// </summary>
    public static bool IsDue(int daysLeft, int? lastNoticeDaysLeft)
    {
        if (daysLeft < 1 || daysLeft > WindowDays)
        {
            return false; // already expired (nothing left to protect) or still outside the window
        }

        if (lastNoticeDaysLeft is { } last && daysLeft >= last)
        {
            return false; // this bucket (or a closer one) was already announced
        }

        return daysLeft is 30 or 20 or 10 or <= 9;
    }
}
