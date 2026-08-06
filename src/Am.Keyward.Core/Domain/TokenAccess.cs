namespace Am.Keyward.Core.Domain.Software;

/// <summary>
/// Access statistics for one software-client token on one UTC calendar day — a pre-aggregated counter, not
/// a row per request (request-level detail belongs in logs, not the database). Written batched by the
/// access-statistics flush; trimmed by the retention job. Like the token table itself, the statistics
/// tables are installation-global (written by a background job outside any tenant scope, deliberately no
/// tenant query filter / row-level security); reads always filter through the token's (tenant, project).
/// </summary>
public sealed class TokenDailyAccess
{
    public Guid Id { get; private set; }
    public Guid TenantId { get; private set; }
    public Guid TokenId { get; private set; }

    /// <summary>The UTC calendar day the counter belongs to.</summary>
    public DateOnly Date { get; private set; }

    public long RequestCount { get; private set; }

    public TokenDailyAccess(Guid id, Guid tenantId, Guid tokenId, DateOnly date, long requestCount)
    {
        Id = id;
        TenantId = tenantId;
        TokenId = tokenId;
        Date = date;
        RequestCount = requestCount;
    }

    public void Add(long requests) => RequestCount += requests;
}

/// <summary>
/// One client IP a token has been seen from, with its first/last sighting. This is both the per-token IP
/// history shown in the statistics UI and the "known IPs" set behind the new-IP alert. Stale rows age out
/// with the statistics retention, so an IP absent for the whole retention window counts as new again.
/// </summary>
public sealed class TokenAccessIp
{
    public Guid Id { get; private set; }
    public Guid TenantId { get; private set; }
    public Guid TokenId { get; private set; }
    public string IpAddress { get; private set; }
    public DateTimeOffset FirstSeenAt { get; private set; }
    public DateTimeOffset LastSeenAt { get; private set; }

    public TokenAccessIp(Guid id, Guid tenantId, Guid tokenId, string ipAddress, DateTimeOffset firstSeenAt, DateTimeOffset lastSeenAt)
    {
        if (string.IsNullOrWhiteSpace(ipAddress))
        {
            throw new ArgumentException("IP address required.", nameof(ipAddress));
        }

        Id = id;
        TenantId = tenantId;
        TokenId = tokenId;
        IpAddress = ipAddress.Trim();
        FirstSeenAt = firstSeenAt;
        LastSeenAt = lastSeenAt;
    }

    public void Touch(DateTimeOffset at) => LastSeenAt = at;
}

/// <summary>What made a token's access pattern noteworthy.</summary>
public enum TokenAccessAlertKind
{
    /// <summary>The token was used from an IP it has never been seen from before (the classic leak signal).</summary>
    NewIpAddress = 0,

    /// <summary>The token was used again after a long silence (it looked retired, then something woke up).</summary>
    ResumedAfterSilence = 1,

    /// <summary>A monitored token's heartbeat stayed out longer than allowed — the consumer looks dead
    /// (<see cref="TokenAccessMonitor"/>, dead-man's switch).</summary>
    HeartbeatMissed = 2,

    /// <summary>A monitored token's heartbeat returned after a down transition (all-clear).</summary>
    HeartbeatRecovered = 3,
}

/// <summary>
/// A rule-based access-pattern alert for one token. Alerts are always visible in the statistics UI;
/// <see cref="EmailedAt"/> tracks whether the (opt-in) notification mail went out, so the mail job never
/// sends one twice. Aged out with the statistics retention.
/// </summary>
public sealed class TokenAccessAlert
{
    public Guid Id { get; private set; }
    public Guid TenantId { get; private set; }
    public Guid TokenId { get; private set; }
    public TokenAccessAlertKind Kind { get; private set; }

    /// <summary>The IP involved (the new IP, or the IP that broke the silence). Null when unknown.</summary>
    public string? IpAddress { get; private set; }

    public DateTimeOffset CreatedAt { get; private set; }
    public DateTimeOffset? EmailedAt { get; private set; }

    public TokenAccessAlert(Guid id, Guid tenantId, Guid tokenId, TokenAccessAlertKind kind, string? ipAddress, DateTimeOffset createdAt)
    {
        Id = id;
        TenantId = tenantId;
        TokenId = tokenId;
        Kind = kind;
        IpAddress = string.IsNullOrWhiteSpace(ipAddress) ? null : ipAddress.Trim();
        CreatedAt = createdAt;
    }

    public void MarkEmailed(DateTimeOffset at) => EmailedAt ??= at;
}
