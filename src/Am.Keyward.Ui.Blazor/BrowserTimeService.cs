namespace Am.Keyward.Ui.Blazor;

/// <summary>
/// Per-circuit holder for the connected browser's time zone, so UTC timestamps from the database can be
/// shown in the viewer's local time (store UTC, display local). The zone is detected once via JS interop
/// after the first interactive render of <c>KeywardUi</c>; until then <see cref="ToLocal"/> returns the
/// UTC value. Scoped lifetime (one per Blazor circuit), registered by <c>AddKeywardUi</c>.
/// </summary>
public sealed class BrowserTimeService
{
    private TimeZoneInfo? _tz;

    /// <summary>Raised once the browser time zone is known, so already-rendered timestamps refresh.</summary>
    public event Action? Changed;

    /// <summary>True once the browser time zone has been resolved.</summary>
    public bool IsReady => _tz is not null;

    /// <summary>
    /// Sets the browser time zone. Prefers the IANA id (DST-correct via the OS/ICU database); falls back
    /// to a fixed-offset zone built from the browser's reported offset when the id can't be resolved.
    /// </summary>
    /// <param name="ianaId">e.g. "Europe/Zurich" from Intl.DateTimeFormat().resolvedOptions().timeZone.</param>
    /// <param name="offsetMinutes">Date.getTimezoneOffset(): minutes to ADD to local to reach UTC.</param>
    public void SetTimeZone(string? ianaId, int offsetMinutes)
    {
        TimeZoneInfo? tz = null;
        if (!string.IsNullOrWhiteSpace(ianaId))
        {
            try
            {
                tz = TimeZoneInfo.FindSystemTimeZoneById(ianaId);
            }
            catch
            {
                // Unknown id on this OS — fall through to the offset-based zone.
            }
        }

        // getTimezoneOffset() is inverted relative to the actual UTC offset (UTC+2 => -120),
        // so the real offset is its negation.
        tz ??= TimeZoneInfo.CreateCustomTimeZone("browser", TimeSpan.FromMinutes(-offsetMinutes), "Browser", "Browser");

        _tz = tz;
        Changed?.Invoke();
    }

    /// <summary>Converts a timestamp to the browser's local time; returns UTC until the zone is known.</summary>
    public DateTimeOffset ToLocal(DateTimeOffset value)
        => _tz is null ? value.ToUniversalTime() : TimeZoneInfo.ConvertTime(value, _tz);

    /// <summary>
    /// Interprets a wall-clock value entered by the user (e.g. a datetime-local input) as browser-local
    /// time and converts it to the UTC instant; treats it as UTC until the zone is known.
    /// </summary>
    public DateTimeOffset ToUtc(DateTime localWallTime)
    {
        var unspecified = DateTime.SpecifyKind(localWallTime, DateTimeKind.Unspecified);
        return _tz is null
            ? new DateTimeOffset(unspecified, TimeSpan.Zero)
            : new DateTimeOffset(TimeZoneInfo.ConvertTimeToUtc(unspecified, _tz), TimeSpan.Zero);
    }

    public string Format(DateTimeOffset value, string format) => ToLocal(value).ToString(format);
}
