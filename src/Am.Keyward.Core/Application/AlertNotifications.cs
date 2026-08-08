using Am.Keyward.Core.Domain.Software;

namespace Am.Keyward.Core.Application;

/// <summary>
/// One administrator who opted into a notification category and administers the tenant an alert belongs to.
/// The e-mail address is deliberately NOT part of this record: mapping a Keyward user onto a mailbox is the
/// host's identity concern, and a host may deliver through channels other than mail (an in-app message, a
/// chat webhook) where no address exists at all.
/// </summary>
public sealed record KeywardAlertRecipient(Guid UserId, string ExternalId);

/// <summary>One alert as it should read in the notification, with token, project and environment already resolved.</summary>
public sealed record KeywardTokenAlertLine(
    TokenAccessAlertKind Kind,
    string TokenName,
    string ProjectName,
    string EnvironmentName,
    string? IpAddress,
    DateTimeOffset CreatedAt);

/// <summary>One token nearing expiry, with project and environment already resolved.</summary>
public sealed record KeywardTokenExpiryLine(
    string TokenName,
    string ProjectName,
    string EnvironmentName,
    int DaysLeft,
    DateTimeOffset ExpiresAt);

/// <summary>
/// Delivers administrative alerts to the administrators who opted into them. Two categories exist and are
/// delivered separately because they have different audiences and frequencies: heartbeat monitoring
/// (a monitored token silent past its deadline, or recovered) and access patterns (a token used from a
/// never-seen IP, or active again after a long silence).
/// <para>
/// This is a PORT, and it is the seam that lets alerts leave an embedded Keyward at all. Detection and the
/// bookkeeping around it are infrastructure and ship with <c>AddKeyward</c>; rendering and delivery need the
/// host's identity (which mailbox belongs to a user), its texts and its transport, so they live here. The
/// standalone shell implements it with Keyward's branded mail; an embedding host SHOULD implement it against
/// its own notification system so the alerts look and route like the rest of that application.
/// </para>
/// <para>
/// When no implementation is registered the alert poller says so once, loudly, instead of discarding alerts
/// in silence — a dead man's switch that cannot reach anyone is worse than none, because it looks healthy.
/// </para>
/// </summary>
public interface IKeywardAlertPresenter
{
    /// <summary>
    /// Whether the HOST decides who hears about an alert. Default <c>false</c>: Keyward filters by its own
    /// per-user opt-ins (the notification switches on the Keyward profile), which is right for the
    /// standalone shell where that profile is the only place to configure them.
    /// <para>
    /// A host with its own subscription model should return <c>true</c>. Keyward then passes every
    /// administrator of the tenant and applies no opt-in of its own, so notifications are configured in ONE
    /// place — the host's. Otherwise the two opt-ins stack: a user subscribed in the host still hears
    /// nothing because a second switch, in a settings page they never visit, defaults to off.
    /// </para>
    /// </summary>
    bool OwnsRecipientSelection => false;

    /// <summary>
    /// Delivers one tenant's fresh alerts of one category to the given recipients. Returns how many
    /// recipients were actually reached; the caller marks the alerts as notified only on a non-zero result,
    /// so a host that is temporarily unable to deliver keeps them pending instead of losing them.
    /// </summary>
    /// <param name="tenantId">The tenant the alerts belong to.</param>
    /// <param name="monitoring"><c>true</c> for heartbeat monitoring, <c>false</c> for access patterns.</param>
    Task<int> NotifyTokenAlertsAsync(
        Guid tenantId,
        bool monitoring,
        IReadOnlyList<KeywardAlertRecipient> recipients,
        IReadOnlyList<KeywardTokenAlertLine> lines,
        CancellationToken ct = default);

    /// <summary>
    /// Delivers one tenant's tokens that are nearing expiry, on the notice schedule. Returns how many
    /// recipients were reached; the caller records the notice only on a non-zero result, so a notice is not
    /// lost while nobody has opted in yet.
    /// </summary>
    Task<int> NotifyTokenExpiryAsync(
        Guid tenantId,
        IReadOnlyList<KeywardAlertRecipient> recipients,
        IReadOnlyList<KeywardTokenExpiryLine> lines,
        CancellationToken ct = default);
}
