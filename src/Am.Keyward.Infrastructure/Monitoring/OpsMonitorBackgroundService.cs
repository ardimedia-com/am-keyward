using System.Data.Common;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Infrastructure.Auth;
using Am.Keyward.Infrastructure.Crypto;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Am.Keyward.Infrastructure.Monitoring;

/// <summary>
/// Periodic compliance/availability monitor. On an interval it: re-runs the key-ownership check (an Unknown verdict
/// from startup, or a database swapped under the running app), verifies the backup/restore KEK integrity (every
/// stored envelope resolves under an available KEK), verifies each tenant's audit hash chain (incrementally from the
/// last checkpoint every hour, in full once a day) and records the verified heads as out-of-band anchors, verifies the
/// break-glass trail, and counts software-client tokens nearing expiry. Findings are published to
/// <see cref="OpsHealthSnapshot"/> for the health endpoint to read cheaply, and anomalies are logged as warnings so an
/// operator's log pipeline can alert on them. Best-effort: failures are logged and never crash the host.
/// </summary>
public sealed class OpsMonitorBackgroundService(
    IServiceScopeFactory scopeFactory,
    OpsHealthSnapshot snapshot,
    IClock clock,
    ILogger<OpsMonitorBackgroundService> logger) : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromHours(1);
    private static readonly TimeSpan StartupDelay = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan FullAuditVerificationInterval = TimeSpan.FromDays(1);
    private const int ExpiryWindowDays = 7;

    // Throttle the "database unreachable" message: log it once, then stay quiet on the hourly interval until
    // the connection recovers, so a not-yet-provisioned environment does not spam the operator's alerts.
    private bool databaseUnavailableLogged;

    // The first pass after a start is always a full audit-chain walk (there are no checkpoints yet anyway).
    private DateTimeOffset lastFullAuditVerification = DateTimeOffset.MinValue;

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

            // Key ownership first: it is the one check whose verdict gates the crypto path. Never throws for an
            // unreachable database (it keeps the previous verdict and logs).
            var keyIntegrity = sp.GetRequiredService<KeywardKeyIntegrityState>();
            var ownership = await this.RecheckKeyOwnershipAsync(keyIntegrity, ct).ConfigureAwait(false);

            // Trusted, tenant-less maintenance sweep: read across every tenant (grant the RLS read bypass for
            // this scope, before any DbContext connection is opened). Reads only — the anchors go to a file.
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

            var anchorTrail = await VerifyAnchorTrailAsync(sp, ct).ConfigureAwait(false);
            var breakGlassTrail = await VerifyBreakGlassTrailAsync(sp, ct).ConfigureAwait(false);

            var expiring = await CountExpiringTokensAsync(sp, ct).ConfigureAwait(false);
            if (expiring > 0)
            {
                logger.LogWarning(
                    "{Count} software-client token(s) expire within {Days} day(s) — rotate them before they lapse.",
                    expiring, ExpiryWindowDays);
            }

            snapshot.Publish(new OpsHealthSnapshot.Reading(
                clock.UtcNow, kek, auditIntact, firstBroken, expiring, ownership, breakGlassTrail, anchorTrail));

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
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(ex, "Ops monitor run failed.");
        }
    }

    private async Task<KekIntegrityStatus> RecheckKeyOwnershipAsync(KeywardKeyIntegrityState state, CancellationToken ct)
    {
        try
        {
            return await state.RecheckAsync(ct).ConfigureAwait(false);
        }
        catch (InvalidOperationException ex)
        {
            // A hand-wired state without a scope factory: report what it holds.
            logger.LogDebug(ex, "Key-ownership recheck is not available in this host.");
            return state.Status;
        }
    }

    private async Task<(bool Intact, long? FirstBroken)> VerifyAuditChainsAsync(IServiceProvider sp, CancellationToken ct)
    {
        var db = sp.GetRequiredService<KeywardDbContext>();
        var verifier = sp.GetRequiredService<IAuditChainVerifier>();
        var scopeSetter = sp.GetRequiredService<ITenantScopeSetter>();
        var checkpoints = sp.GetService<AuditChainCheckpoints>();
        var anchors = sp.GetService<AuditHeadAnchorLog>();

        var now = clock.UtcNow;
        var full = now - lastFullAuditVerification >= FullAuditVerificationInterval;

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
            var status = verifier is DbAuditChainVerifier incremental
                ? await incremental.VerifyAsync(tenantId, full, ct).ConfigureAwait(false)
                : await verifier.VerifyAsync(tenantId, ct).ConfigureAwait(false);
            if (!status.IsIntact)
            {
                logger.LogError("Audit chain of tenant {TenantId} is broken: {Detail}", tenantId, status.Detail);
                return (false, status.FirstBrokenSequence);
            }

            // The verified head goes out of band, so cutting entries off the end later is caught.
            if (anchors is { IsEnabled: true } && checkpoints is not null
                && checkpoints.TryGet(tenantId, out long sequence, out string hash))
            {
                try
                {
                    await anchors.RecordAsync(tenantId, sequence, hash, ct).ConfigureAwait(false);
                }
                catch (IOException ex)
                {
                    logger.LogWarning(ex, "The audit head anchor could not be written to {Path}.", anchors.FilePath);
                }
            }
        }

        if (full)
        {
            lastFullAuditVerification = now;
        }

        return (true, null);
    }

    private async Task<HashChainVerification?> VerifyAnchorTrailAsync(IServiceProvider sp, CancellationToken ct)
    {
        var anchors = sp.GetService<AuditHeadAnchorLog>();
        if (anchors is not { IsEnabled: true })
        {
            return null;
        }

        try
        {
            var result = await anchors.VerifyAsync(ct).ConfigureAwait(false);
            if (!result.IsIntact)
            {
                logger.LogError("The audit anchor file {Path} failed verification: {Detail}", anchors.FilePath, result.Detail);
            }

            return result;
        }
        catch (IOException ex)
        {
            logger.LogWarning(ex, "The audit anchor file {Path} could not be read.", anchors.FilePath);
            return null;
        }
    }

    private async Task<HashChainVerification?> VerifyBreakGlassTrailAsync(IServiceProvider sp, CancellationToken ct)
    {
        try
        {
            if (sp.GetService<IBreakGlassSink>() is not FileBreakGlassSink sink)
            {
                return null;   // a host-provided sink verifies itself
            }

            var result = await sink.VerifyAsync(ct).ConfigureAwait(false);
            if (!result.IsIntact)
            {
                logger.LogError(
                    "The break-glass trail {Path} failed verification at line {Line}: {Detail}",
                    sink.FilePath, result.FirstBrokenLine, result.Detail);
            }
            else if (result.DamagedLines.Count > 0)
            {
                logger.LogWarning("The break-glass trail {Path}: {Detail}", sink.FilePath, result.Detail);
            }

            return result;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            logger.LogError(ex, "The break-glass trail could not be verified.");
            return null;
        }
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
