using Am.Keyward.Core.Abstractions;
using Am.Keyward.Infrastructure.Monitoring;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Am.Keyward.Tests;

/// <summary>
/// The ops-monitor health check maps the cached monitoring snapshot to a health status without touching
/// the database: KEK-integrity or audit-chain failures are Unhealthy, imminent token expiry or a stale
/// snapshot are Degraded, and a clean recent reading is Healthy.
/// </summary>
[TestClass]
public class OpsMonitorHealthCheckTests
{
    private static readonly DateTimeOffset Now = new(2026, 6, 22, 12, 0, 0, TimeSpan.Zero);

    private sealed class FixedClock(DateTimeOffset now) : IClock
    {
        public DateTimeOffset UtcNow { get; } = now;
    }

    private static async Task<HealthCheckResult> CheckAsync(OpsHealthSnapshot.Reading reading)
    {
        var snapshot = new OpsHealthSnapshot();
        snapshot.Publish(reading);
        var check = new OpsMonitorHealthCheck(snapshot, new FixedClock(Now));
        return await check.CheckHealthAsync(new HealthCheckContext());
    }

    [TestMethod, TestCategory("Unit")]
    public async Task Healthy_before_first_run()
    {
        var result = await CheckAsync(new OpsHealthSnapshot.Reading(default, null, true, null, 0));
        Assert.AreEqual(HealthStatus.Healthy, result.Status);
    }

    [TestMethod, TestCategory("Unit")]
    public async Task Unhealthy_when_kek_integrity_inconsistent()
    {
        var report = new KekIntegrityReport(10, [new KekIntegrityIssue("SecretVersion", Guid.NewGuid(), "kek:v1")]);
        var result = await CheckAsync(new OpsHealthSnapshot.Reading(Now, report, true, null, 0));
        Assert.AreEqual(HealthStatus.Unhealthy, result.Status);
    }

    [TestMethod, TestCategory("Unit")]
    public async Task Unhealthy_when_audit_chain_broken()
    {
        var report = new KekIntegrityReport(10, []);
        var result = await CheckAsync(new OpsHealthSnapshot.Reading(Now, report, AuditChainIntact: false, 5, 0));
        Assert.AreEqual(HealthStatus.Unhealthy, result.Status);
    }

    [TestMethod, TestCategory("Unit")]
    public async Task Degraded_when_snapshot_is_stale()
    {
        var report = new KekIntegrityReport(10, []);
        var stale = Now.AddHours(-5);
        var result = await CheckAsync(new OpsHealthSnapshot.Reading(stale, report, true, null, 0));
        Assert.AreEqual(HealthStatus.Degraded, result.Status);
    }

    [TestMethod, TestCategory("Unit")]
    public async Task Degraded_when_tokens_expiring_soon()
    {
        var report = new KekIntegrityReport(10, []);
        var result = await CheckAsync(new OpsHealthSnapshot.Reading(Now, report, true, null, 3));
        Assert.AreEqual(HealthStatus.Degraded, result.Status);
    }

    [TestMethod, TestCategory("Unit")]
    public async Task Healthy_when_clean_and_fresh()
    {
        var report = new KekIntegrityReport(10, []);
        var result = await CheckAsync(new OpsHealthSnapshot.Reading(Now, report, true, null, 0));
        Assert.AreEqual(HealthStatus.Healthy, result.Status);
    }
}
