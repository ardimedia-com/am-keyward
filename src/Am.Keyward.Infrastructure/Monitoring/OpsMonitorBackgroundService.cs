using System.Data.Common;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Am.Keyward.Infrastructure.Monitoring;

/// <summary>
/// Periodic compliance/availability monitor. On an interval it: verifies the backup/restore KEK integrity
/// (every stored envelope resolves under an available KEK), verifies each tenant's audit hash chain, and
/// counts software-client tokens nearing expiry. Findings are published to <see cref="OpsHealthSnapshot"/>
/// for the health endpoint to read cheaply, and anomalies are logged as warnings so an operator's log
/// pipeline can alert on them. Best-effort: failures are logged and never crash the host.
/// </summary>
public sealed class OpsMonitorBackgroundService(
    IServiceScopeFactory scopeFactory,
    OpsHealthSnapshot snapshot,
    IClock clock,
    ILogger<OpsMonitorBackgroundService> logger) : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromHours(1);
    private static readonly TimeSpan StartupDelay = TimeSpan.FromMinutes(2);
    private const int ExpiryWindowDays = 7;

    // Throttle the "database unreachable" message: log it once, then stay quiet on the hourly interval until
    // the connection recovers, so a not-yet-provisioned environment does not spam the operator's alerts.
    private bool databaseUnavailableLogged;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await Task.Delay(StartupDelay, stoppingToken).ConfigureAwait(false);
            using var timer = new PeriodicTimer(Interval);
            do
            {
                await RunAsync(stoppingToken).ConfigureAwait(false);
            }
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
            // Host shutting down — expected.
        }
    }

    private async Task RunAsync(CancellationToken ct)
    {
        try
        {
            using var scope = scopeFactory.CreateScope();
            var sp = scope.ServiceProvider;

            // Trusted, tenant-less maintenance sweep: read across every tenant (grant the RLS read bypass for
            // this scope, before any DbContext connection is opened). Reads only — no writes happen here.
            sp.GetRequiredService<Tenancy.SystemReadScope>().Enabled = true;

            var kek = await sp.GetRequiredService<IKekIntegrityVerifier>().VerifyAsync(ct).ConfigureAwait(false);
            if (!kek.IsConsistent)
            {
                logger.LogError(
                    "KEK integrity check found {Count} envelope(s) wrapped under an unavailable KEK — the database may have been restored without its matching KEK store. Decryption of those values will fail.",
                    kek.Unresolvable.Count);
            }

            var (auditIntact, firstBroken) = await VerifyAuditChainsAsync(sp, ct).ConfigureAwait(false);
            if (!auditIntact)
            {
                logger.LogError(
                    "Audit hash chain verification failed at sequence {Sequence} — an audit entry may have been altered or deleted out of band.",
                    firstBroken);
            }

            var expiring = await CountExpiringTokensAsync(sp, ct).ConfigureAwait(false);
            if (expiring > 0)
            {
                logger.LogWarning(
                    "{Count} software-client token(s) expire within {Days} day(s) — rotate them before they lapse.",
                    expiring, ExpiryWindowDays);
            }

            snapshot.Publish(new OpsHealthSnapshot.Reading(clock.UtcNow, kek, auditIntact, firstBroken, expiring));

            if (databaseUnavailableLogged)
            {
                logger.LogInformation("Keyward database is reachable again — monitoring resumed.");
                databaseUnavailableLogged = false;
            }
        }
        catch (DbException ex)
        {
            // The database is unreachable or not provisioned in THIS environment — e.g. Keyward is enabled but
            // its connection string is not set for this stage (so it falls back to a default/localhost server),
            // or the amkeyward_app login / amkeyward schema does not exist yet. That is an operator/config gap,
            // not an internal fault, so log ONE clear, actionable message and stay quiet on the hourly interval
            // until the connection recovers — instead of a raw SqlException stack every hour.
            if (!databaseUnavailableLogged)
            {
                logger.LogWarning(ex,
                    "Keyward could not reach its database, so this monitoring run was skipped. Keyward is enabled "
                    + "but its database is unreachable or not provisioned in this environment. Verify the Keyward "
                    + "connection string points at this environment's SQL Server, and that the amkeyward_app login "
                    + "and the amkeyward schema exist — or disable Keyward (Keyward:Enabled=false) until it is "
                    + "provisioned. Keyward is unavailable meanwhile. This is logged once; it will log again only "
                    + "after the database recovers.");
                databaseUnavailableLogged = true;
            }
            else
            {
                logger.LogDebug(ex, "Keyward monitoring skipped again — database still unreachable.");
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Ops monitor run failed.");
        }
    }

    private async Task<(bool Intact, long? FirstBroken)> VerifyAuditChainsAsync(IServiceProvider sp, CancellationToken ct)
    {
        var db = sp.GetRequiredService<KeywardDbContext>();
        var verifier = sp.GetRequiredService<IAuditChainVerifier>();
        var scopeSetter = sp.GetRequiredService<ITenantScopeSetter>();

        // Distinct tenants that have audit entries, plus the null (personal/global) chain.
        var tenantIds = await db.AuditEntries
            .IgnoreQueryFilters()
            .Select(a => a.TenantId)
            .Distinct()
            .ToListAsync(ct)
            .ConfigureAwait(false);

        foreach (var tenantId in tenantIds)
        {
            scopeSetter.SetTenant(tenantId);
            var status = await verifier.VerifyAsync(tenantId, ct).ConfigureAwait(false);
            if (!status.IsIntact)
            {
                return (false, status.FirstBrokenSequence);
            }
        }

        return (true, null);
    }

    private async Task<int> CountExpiringTokensAsync(IServiceProvider sp, CancellationToken ct)
    {
        var db = sp.GetRequiredService<KeywardDbContext>();
        var now = clock.UtcNow;
        var horizon = now.AddDays(ExpiryWindowDays);
        return await db.SoftwareClientTokens
            .Where(t => t.RevokedAt == null && t.ExpiresAt != null && t.ExpiresAt > now && t.ExpiresAt <= horizon)
            .CountAsync(ct)
            .ConfigureAwait(false);
    }
}
