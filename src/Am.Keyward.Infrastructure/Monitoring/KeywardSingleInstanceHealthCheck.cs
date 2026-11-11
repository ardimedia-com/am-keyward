using Am.Keyward.Infrastructure.Persistence;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Am.Keyward.Infrastructure.Monitoring;

/// <summary>
/// Reports whether this process is the only AM KEYWARD instance on its database (see <see cref="KeywardInstanceLease"/>):
/// Unhealthy when another instance holds the lease — one instance per database is the supported deployment — Degraded
/// while it could not be checked yet, Healthy otherwise. Register it with the «ready» tag.
/// </summary>
public sealed class KeywardSingleInstanceHealthCheck(KeywardInstanceLeaseState state) : IHealthCheck
{
    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default) =>
        Task.FromResult(state.Status switch
        {
            KeywardInstanceLeaseStatus.Held => HealthCheckResult.Healthy("This is the only AM KEYWARD instance on the database."),
            KeywardInstanceLeaseStatus.HeldElsewhere => HealthCheckResult.Unhealthy(
                state.Detail ?? "Another AM KEYWARD instance is running against the same database."),
            _ => HealthCheckResult.Degraded(state.Detail ?? "The single-instance check has not completed yet."),
        });
}
