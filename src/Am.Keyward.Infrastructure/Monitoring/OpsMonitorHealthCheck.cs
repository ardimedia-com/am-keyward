using Am.Keyward.Core.Abstractions;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Am.Keyward.Infrastructure.Monitoring;

/// <summary>
/// Reports the latest <see cref="OpsHealthSnapshot"/> produced by the periodic ops monitor without
/// re-scanning the database. Unhealthy when the KEK integrity sweep found unresolvable envelopes or the
/// audit hash chain failed verification; Degraded when tokens are expiring soon or the snapshot is stale
/// (the monitor has not produced a fresh reading recently).
/// </summary>
public sealed class OpsMonitorHealthCheck(OpsHealthSnapshot snapshot, IClock clock) : IHealthCheck
{
    private static readonly TimeSpan StaleAfter = TimeSpan.FromHours(3);

    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        var reading = snapshot.Current;

        if (reading.LastRunUtc == default)
        {
            return Task.FromResult(HealthCheckResult.Healthy("Ops monitor has not completed its first run yet."));
        }

        var data = new Dictionary<string, object>
        {
            ["lastRunUtc"] = reading.LastRunUtc,
            ["kekChecked"] = reading.KekIntegrity?.Checked ?? 0,
            ["kekUnresolvable"] = reading.KekIntegrity?.Unresolvable.Count ?? 0,
            ["auditChainIntact"] = reading.AuditChainIntact,
            ["tokensExpiringSoon"] = reading.TokensExpiringSoon,
        };

        if (reading.KekIntegrity is { IsConsistent: false } kek)
        {
            return Task.FromResult(HealthCheckResult.Unhealthy(
                $"{kek.Unresolvable.Count} encrypted value(s) reference an unavailable KEK.", data: data));
        }

        if (!reading.AuditChainIntact)
        {
            return Task.FromResult(HealthCheckResult.Unhealthy(
                $"Audit hash chain failed verification at sequence {reading.FirstBrokenAuditSequence}.", data: data));
        }

        if (clock.UtcNow - reading.LastRunUtc > StaleAfter)
        {
            return Task.FromResult(HealthCheckResult.Degraded("Ops monitor snapshot is stale.", data: data));
        }

        if (reading.TokensExpiringSoon > 0)
        {
            return Task.FromResult(HealthCheckResult.Degraded(
                $"{reading.TokensExpiringSoon} software-client token(s) expire soon.", data: data));
        }

        return Task.FromResult(HealthCheckResult.Healthy("KEK integrity and audit chain verified; no imminent token expiry.", data));
    }
}
