using Am.Keyward.Core.Domain.Software;

namespace Am.Keyward.Tests;

/// <summary>
/// The watch-window calendar math behind heartbeat monitoring: silence must accrue only inside the
/// configured weekday/time-of-day window, so a Monday-to-Friday job does not false-alarm on Monday morning
/// after its scheduled weekend pause.
/// </summary>
[TestClass]
public class WatchWindowCalculatorTests
{
    private static readonly TimeZoneInfo Utc = TimeZoneInfo.Utc;
    private const byte AllDays = TokenAccessMonitor.AllDays;
    private const byte MondayToFriday = 0b0001_1111;

    // 2026-08-03 is a Monday.
    private static DateTimeOffset MondayAt(int hour) => new(2026, 8, 3, hour, 0, 0, TimeSpan.Zero);
    private static DateTimeOffset FridayAt(int hour) => new(2026, 8, 7, hour, 0, 0, TimeSpan.Zero);
    private static DateTimeOffset SaturdayAt(int hour) => new(2026, 8, 8, hour, 0, 0, TimeSpan.Zero);
    private static DateTimeOffset NextMondayAt(int hour) => new(2026, 8, 10, hour, 0, 0, TimeSpan.Zero);

    [TestMethod, TestCategory("Domain")]
    public void Always_open_window_is_the_plain_difference()
    {
        var elapsed = WatchWindowCalculator.ElapsedInWindow(MondayAt(8), MondayAt(12), AllDays, null, null, Utc);
        Assert.AreEqual(TimeSpan.FromHours(4), elapsed);
    }

    [TestMethod, TestCategory("Domain")]
    public void Reversed_range_is_zero()
    {
        Assert.AreEqual(TimeSpan.Zero, WatchWindowCalculator.ElapsedInWindow(MondayAt(12), MondayAt(8), AllDays, null, null, Utc));
    }

    [TestMethod, TestCategory("Domain")]
    public void Weekend_does_not_count_for_a_weekday_window()
    {
        // Friday 08:00 → next Monday 08:00: only Friday's remaining 16 h and Monday's first 8 h count.
        var elapsed = WatchWindowCalculator.ElapsedInWindow(FridayAt(8), NextMondayAt(8), MondayToFriday, null, null, Utc);
        Assert.AreEqual(TimeSpan.FromHours(24), elapsed);
    }

    [TestMethod, TestCategory("Domain")]
    public void Monday_morning_after_a_weekday_job_stays_under_a_daily_threshold()
    {
        // The false-alarm scenario from the analysis: a daily Mo–Fr job last ran Friday 06:00; on Monday
        // 07:00 the absolute silence is 73 h, but the in-window silence is 18 h (Friday) + 7 h (Monday).
        var elapsed = WatchWindowCalculator.ElapsedInWindow(FridayAt(6), NextMondayAt(7), MondayToFriday, null, null, Utc);
        Assert.AreEqual(TimeSpan.FromHours(25), elapsed);
        Assert.IsTrue(elapsed < TimeSpan.FromHours(26), "a 26 h threshold must not fire on Monday morning");
    }

    [TestMethod, TestCategory("Domain")]
    public void Time_of_day_window_counts_only_working_hours()
    {
        // Monday 07:00–18:00 window; from Monday 06:00 to Monday 20:00 exactly the window's 11 h count.
        var elapsed = WatchWindowCalculator.ElapsedInWindow(
            MondayAt(6), MondayAt(20), AllDays, new TimeOnly(7, 0), new TimeOnly(18, 0), Utc);
        Assert.AreEqual(TimeSpan.FromHours(11), elapsed);
    }

    [TestMethod, TestCategory("Domain")]
    public void Overnight_window_spans_midnight_as_two_segments()
    {
        // 22:00–06:00 window: Monday 20:00 → Tuesday 08:00 passes Monday 22–24 and Tuesday 00–06.
        var elapsed = WatchWindowCalculator.ElapsedInWindow(
            MondayAt(20), MondayAt(20).AddHours(12), AllDays, new TimeOnly(22, 0), new TimeOnly(6, 0), Utc);
        Assert.AreEqual(TimeSpan.FromHours(8), elapsed);
    }

    [TestMethod, TestCategory("Domain")]
    public void Window_times_follow_the_given_zone()
    {
        // 07:00–18:00 in UTC+2: the window opens at 05:00 UTC. From 04:00 UTC to 06:00 UTC one hour counts.
        var zurich = TimeZoneInfo.CreateCustomTimeZone("test-plus2", TimeSpan.FromHours(2), "UTC+2", "UTC+2");
        var elapsed = WatchWindowCalculator.ElapsedInWindow(
            MondayAt(4), MondayAt(6), AllDays, new TimeOnly(7, 0), new TimeOnly(18, 0), zurich);
        Assert.AreEqual(TimeSpan.FromHours(1), elapsed);
    }

    [TestMethod, TestCategory("Domain")]
    public void Next_deadline_skips_the_weekend()
    {
        // Reference Friday 06:00, 26 h allowed inside Mo–Fr: 18 h remain on Friday, the next 8 h accrue
        // on Monday — the deadline is Monday 08:00, not Saturday.
        var deadline = WatchWindowCalculator.NextDeadline(
            FridayAt(6), TimeSpan.FromHours(26), MondayToFriday, null, null, Utc);
        Assert.AreEqual(NextMondayAt(8), deadline);
    }

    [TestMethod, TestCategory("Domain")]
    public void Next_deadline_for_always_open_window_is_reference_plus_silence()
    {
        var deadline = WatchWindowCalculator.NextDeadline(MondayAt(6), TimeSpan.FromHours(26), AllDays, null, null, Utc);
        Assert.AreEqual(MondayAt(6).AddHours(26), deadline);
    }

    [TestMethod, TestCategory("Domain")]
    public void Reference_on_an_unwatched_day_starts_accruing_at_the_next_window()
    {
        // Reference Saturday noon, Mo–Fr window, 4 h allowed → deadline Monday 04:00.
        var deadline = WatchWindowCalculator.NextDeadline(
            SaturdayAt(12), TimeSpan.FromHours(4), MondayToFriday, null, null, Utc);
        Assert.AreEqual(NextMondayAt(4), deadline);
    }

    [TestMethod, TestCategory("Domain")]
    public void Day_mask_uses_iso_order_monday_first()
    {
        Assert.IsTrue(WatchWindowCalculator.IsWatchedDay(DayOfWeek.Monday, 0b000_0001));
        Assert.IsTrue(WatchWindowCalculator.IsWatchedDay(DayOfWeek.Sunday, 0b100_0000));
        Assert.IsFalse(WatchWindowCalculator.IsWatchedDay(DayOfWeek.Saturday, MondayToFriday));
        Assert.IsFalse(WatchWindowCalculator.IsWatchedDay(DayOfWeek.Sunday, MondayToFriday));
    }

    [TestMethod, TestCategory("Domain")]
    public void Monitor_validates_schedule()
    {
        var monitor = NewMonitor();
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => monitor.SetSchedule(0, AllDays, null, null));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => monitor.SetSchedule(60, 0, null, null));
        Assert.ThrowsExactly<ArgumentException>(() => monitor.SetSchedule(60, AllDays, new TimeOnly(7, 0), null));
        Assert.ThrowsExactly<ArgumentException>(() => monitor.SetSchedule(60, AllDays, new TimeOnly(7, 0), new TimeOnly(7, 0)));
    }

    [TestMethod, TestCategory("Domain")]
    public void Monitor_state_transition_reports_changes_only()
    {
        var monitor = NewMonitor();
        Assert.AreEqual(TokenMonitorState.Up, monitor.State);
        Assert.IsFalse(monitor.ApplyState(TokenMonitorState.Up, MondayAt(8)));
        Assert.IsTrue(monitor.ApplyState(TokenMonitorState.Down, MondayAt(9)));
        Assert.AreEqual(MondayAt(9), monitor.LastStateChangeAt);
        Assert.IsFalse(monitor.ApplyState(TokenMonitorState.Down, MondayAt(10)));
        Assert.IsTrue(monitor.ApplyState(TokenMonitorState.Up, MondayAt(11)));
    }

    private static TokenAccessMonitor NewMonitor() =>
        new(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), 60, AllDays, null, null, notifyOnRecovery: true, MondayAt(0));
}
