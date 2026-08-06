using Am.Keyward.Core.Domain.Software;

namespace Am.Keyward.Core.Application;

/// <summary>
/// One token's heartbeat-monitor settings and state for the monitoring UI. <see cref="NextDeadline"/> is
/// computed server-side (the watch window is evaluated in the app-wide monitoring time zone, which the UI
/// does not know); null when the monitor is disabled or the window never accumulates the allowed silence.
/// </summary>
public sealed record TokenMonitorInfo(
    Guid TokenId,
    bool Enabled,
    int MaxSilenceMinutes,
    byte WatchDaysMask,
    TimeOnly? WatchStart,
    TimeOnly? WatchEnd,
    bool NotifyOnRecovery,
    DateTimeOffset? SnoozeUntil,
    TokenMonitorState State,
    DateTimeOffset? LastStateChangeAt,
    DateTimeOffset? NextDeadline);

/// <summary>Creates the token's monitor or replaces its settings (the monitor becomes enabled).</summary>
public sealed record UpsertTokenMonitorCommand(
    Guid TenantId,
    Guid TokenId,
    int MaxSilenceMinutes,
    byte WatchDaysMask,
    TimeOnly? WatchStart,
    TimeOnly? WatchEnd,
    bool NotifyOnRecovery,
    Guid? ActorUserId);

/// <summary>
/// Management surface for heartbeat monitoring (the Applications page's Monitoring tab). Mutations are
/// gated on the software-operator predicate and audited, like the token management itself.
/// </summary>
public interface ITokenAccessMonitorService
{
    /// <summary>The monitors of the application's tokens (tokens without a monitor have no entry).</summary>
    Task<IReadOnlyList<TokenMonitorInfo>> ListAsync(Guid tenantId, Guid projectId, CancellationToken ct = default);

    Task UpsertAsync(UpsertTokenMonitorCommand cmd, CancellationToken ct = default);

    /// <summary>Pauses (until an instant) or resumes (null) an existing monitor; it reactivates by itself.</summary>
    Task SnoozeAsync(Guid tenantId, Guid tokenId, DateTimeOffset? until, Guid? actorUserId, CancellationToken ct = default);

    /// <summary>Disables or re-enables an existing monitor without touching its settings.</summary>
    Task SetEnabledAsync(Guid tenantId, Guid tokenId, bool enabled, Guid? actorUserId, CancellationToken ct = default);
}
