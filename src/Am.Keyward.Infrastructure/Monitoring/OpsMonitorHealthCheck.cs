using Am.Keyward.Core.Abstractions;
using Am.Keyward.Infrastructure.Crypto;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Am.Keyward.Infrastructure.Monitoring;

/// <summary>
/// Reports the latest <see cref="OpsHealthSnapshot"/> produced by the periodic ops monitor without
/// re-scanning the database. Unhealthy when the key does not own the database, the KEK integrity sweep found
/// unresolvable envelopes, the audit hash chain (or its out-of-band anchors) failed verification, or the break-glass
/// trail is broken; Degraded when a trail holds damaged lines, tokens are expiring soon or the snapshot is stale (the
/// monitor has not produced a fresh reading recently).
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
            ["keyOwnership"] = reading.KeyOwnership.ToString(),
            ["auditChainIntact"] = reading.AuditChainIntact,
            ["breakGlassTrail"] = reading.BreakGlassTrail switch
            {
                null => "not checked",
                { IsIntact: false } => "broken",
                { DamagedLines.Count: > 0 } => "damaged lines",
                _ => "intact",
            },
            ["tokensExpiringSoon"] = reading.TokensExpiringSoon,
        };

        if (reading.KeyOwnership == KekIntegrityStatus.Conflict)
        {
            return Task.FromResult(HealthCheckResult.Unhealthy(
                "The key-encryption key does not own the data in this database (key-ownership canary).", data: data));
        }

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

        if (reading.BreakGlassTrail is { IsIntact: false } trail)
        {
            return Task.FromResult(HealthCheckResult.Unhealthy(
                $"The break-glass trail failed verification: {trail.Detail}", data: data));
        }

        if (reading.AuditAnchorTrail is { IsIntact: false } anchors)
        {
            return Task.FromResult(HealthCheckResult.Unhealthy(
                $"The audit anchor file failed verification: {anchors.Detail}", data: data));
        }

        if (clock.UtcNow - reading.LastRunUtc > StaleAfter)
        {
            return Task.FromResult(HealthCheckResult.Degraded("Ops monitor snapshot is stale.", data: data));
        }

        if (reading.BreakGlassTrail is { DamagedLines.Count: > 0 } damaged)
        {
            return Task.FromResult(HealthCheckResult.Degraded(
                $"The break-glass trail holds damaged line(s): {damaged.Detail}", data: data));
        }

        if (reading.TokensExpiringSoon > 0)
        {
            return Task.FromResult(HealthCheckResult.Degraded(
                $"{reading.TokensExpiringSoon} software-client token(s) expire soon.", data: data));
        }

        return Task.FromResult(HealthCheckResult.Healthy("KEK integrity and audit chain verified; no imminent token expiry.", data));
    }
}
