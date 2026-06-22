using Am.Keyward.Core.Abstractions;

namespace Am.Keyward.Infrastructure.Monitoring;

/// <summary>
/// The latest result of the periodic ops monitor, published for health checks to read. Updated atomically
/// by <see cref="OpsMonitorBackgroundService"/> so health endpoints never trigger a full database scan on
/// each poll. Registered as a singleton.
/// </summary>
public sealed class OpsHealthSnapshot
{
    /// <summary>One monitor run's findings. <paramref name="LastRunUtc"/> is <c>default</c> before the first run.</summary>
    public sealed record Reading(
        DateTimeOffset LastRunUtc,
        KekIntegrityReport? KekIntegrity,
        bool AuditChainIntact,
        long? FirstBrokenAuditSequence,
        int TokensExpiringSoon);

    private volatile Reading _current = new(default, null, AuditChainIntact: true, null, 0);

    public Reading Current => _current;

    public void Publish(Reading reading) => _current = reading;
}
