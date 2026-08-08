using Am.Keyward.Core.Domain.Software;

namespace Am.Keyward.Core.Application;

/// <summary>
/// The hot-path side of token access statistics: called on every authenticated software-client request,
/// so it must be in-memory, non-blocking and infallible — recording never touches the database and never
/// fails the secret read. A background flush persists the accumulated data (last access on the token,
/// daily counters, seen IPs) and derives the access-pattern alerts.
/// </summary>
public interface ITokenAccessRecorder
{
    void Record(Guid tokenId, string? ipAddress);
}

/// <summary>One day's request counter for one token (UTC calendar day).</summary>
public sealed record TokenDailyAccessInfo(Guid TokenId, DateOnly Date, long RequestCount);

/// <summary>One client IP a token has been seen from.</summary>
public sealed record TokenAccessIpInfo(Guid TokenId, string IpAddress, DateTimeOffset FirstSeenAt, DateTimeOffset LastSeenAt);

/// <summary>One access-pattern alert (also carried in the notification mail when admins opted in).</summary>
public sealed record TokenAccessAlertInfo(Guid TokenId, TokenAccessAlertKind Kind, string? IpAddress, DateTimeOffset CreatedAt);

/// <summary>Read side for the per-application statistics UI. Scoped to one (tenant, application).</summary>
public interface ITokenAccessStatisticsService
{
    /// <summary>
    /// Today's date in the zone the daily counters are bucketed by (the installation's time zone) —
    /// the chart axis must end on this day, not on the viewer's or UTC's notion of "today".
    /// </summary>
    DateOnly CurrentStatisticsDay { get; }

    /// <summary>Daily request counters of the application's tokens for the trailing <paramref name="days"/> days.</summary>
    Task<IReadOnlyList<TokenDailyAccessInfo>> ListDailyAsync(Guid tenantId, Guid projectId, int days, CancellationToken ct = default);

    /// <summary>The IPs the application's tokens have been seen from (within the retention window).</summary>
    Task<IReadOnlyList<TokenAccessIpInfo>> ListIpsAsync(Guid tenantId, Guid projectId, CancellationToken ct = default);

    /// <summary>Recent access-pattern alerts for the application's tokens, newest first.</summary>
    Task<IReadOnlyList<TokenAccessAlertInfo>> ListAlertsAsync(Guid tenantId, Guid projectId, int take = 50, CancellationToken ct = default);
}
