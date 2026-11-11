using System.Data.Common;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Domain.Software;
using Am.Keyward.Infrastructure.Persistence;
using Am.Keyward.Infrastructure.Statistics;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Am.Keyward.Infrastructure.Monitoring;

/// <summary>
/// The dead-man's switch evaluator. The rule-based access alerts fire when an access HAPPENS (they are
/// derived in the statistics flush); a missing heartbeat by definition produces no event, so this service
/// polls: for every enabled, un-snoozed <see cref="TokenAccessMonitor"/> it measures the in-window silence
/// since the token's last access (or the monitor's creation, for a never-used token) and applies the
/// up/down state. Transitions append <see cref="TokenAccessAlert"/> rows, which the statistics UI shows
/// and the opt-in alert mail delivers — mails go out on TRANSITIONS only, a lasting outage does not spam.
/// State and signal both live in the database, so a host restart just re-evaluates against persisted
/// values: missed ticks cause no false alarms, at most a later first detection. Best-effort: failures are
/// logged and never crash the host. Assumes a single running instance (like the other mail/flush jobs);
/// a second instance would evaluate twice (see <c>KeywardInstanceLease</c>).
/// <para>
/// The heartbeat is the later of the persisted <c>LastAccessAt</c> and the not-yet-flushed access in the in-memory
/// accumulator, so the signal does not depend on the statistics flush; and the allowed silence is never taken below
/// <see cref="HeartbeatTiming.MinimumMaxSilenceMinutes"/>, which no flush/check cadence could honour.
/// </para>
/// </summary>
public sealed class TokenAccessMonitorBackgroundService(
    IServiceScopeFactory scopeFactory,
    IOptions<MonitoringOptions> options,
    IOptions<TokenAccessOptions> tokenAccessOptions,
    TokenAccessAccumulator pendingAccesses,
    IClock clock,
    ILogger<TokenAccessMonitorBackgroundService> logger) : BackgroundService
{
    private static readonly TimeSpan StartupDelay = TimeSpan.FromMinutes(2);

    // LastEvaluatedAt is diagnostic; rewriting every monitor row on every tick would be pointless churn.
    private static readonly TimeSpan EvaluationStampInterval = TimeSpan.FromMinutes(15);

    private bool databaseUnavailableLogged;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!options.Value.Enabled)
        {
            logger.LogInformation("Heartbeat monitoring is disabled (Keyward:Monitoring:Enabled=false).");
            return;
        }

        var zone = options.Value.ResolveTimeZone(logger);
        var interval = TimeSpan.FromSeconds(Math.Max(options.Value.CheckIntervalSeconds, 10));

        try
        {
            await Task.Delay(StartupDelay, stoppingToken).ConfigureAwait(false);
            using var timer = new PeriodicTimer(interval);
            do
            {
                await EvaluateAsync(zone, stoppingToken).ConfigureAwait(false);
            }
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
            // Host shutting down — expected.
        }
    }

    /// <summary>One evaluation of every enabled monitor.</summary>
    internal async Task EvaluateAsync(TimeZoneInfo zone, CancellationToken ct)
    {
        try
        {
            using var scope = scopeFactory.CreateScope();
            var dbFactory = scope.ServiceProvider.GetRequiredService<IDbContextFactory<KeywardDbContext>>();
            await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);

            // Monitors, tokens and alerts are installation-global tables (no tenant filter, no RLS), so
            // this sweep needs no tenant scope — the alert rows carry the monitor's TenantId for the reads.
            var monitors = await db.TokenAccessMonitors
                .Where(m => m.Enabled)
                .ToListAsync(ct)
                .ConfigureAwait(false);
            if (monitors.Count == 0)
            {
                return;
            }

            var tokenIds = monitors.Select(m => m.TokenId).ToList();
            var lastAccessByToken = await db.SoftwareClientTokens
                .Where(t => tokenIds.Contains(t.Id))
                .Select(t => new { t.Id, t.LastAccessAt })
                .ToDictionaryAsync(t => t.Id, t => t.LastAccessAt, ct)
                .ConfigureAwait(false);

            // A heartbeat that arrived since the last flush counts now — not one flush interval later.
            foreach (var (tokenId, pendingAt) in pendingAccesses.PeekLastAccess(tokenIds))
            {
                if (lastAccessByToken.GetValueOrDefault(tokenId) is not { } persisted || pendingAt > persisted)
                {
                    lastAccessByToken[tokenId] = pendingAt;
                }
            }

            var minimumSilence = TimeSpan.FromMinutes(HeartbeatTiming.MinimumMaxSilenceMinutes(options.Value, tokenAccessOptions.Value));
            var now = clock.UtcNow;
            foreach (var monitor in monitors)
            {
                if (monitor.SnoozeUntil is { } snooze && snooze > now)
                {
                    continue; // paused — state frozen until the snooze expires
                }

                var reference = lastAccessByToken.GetValueOrDefault(monitor.TokenId) ?? monitor.CreatedAt;
                var silence = WatchWindowCalculator.ElapsedInWindow(
                    reference, now, monitor.WatchDaysMask, monitor.WatchStart, monitor.WatchEnd, zone);
                var allowed = TimeSpan.FromMinutes(monitor.MaxSilenceMinutes);
                var state = silence > (allowed > minimumSilence ? allowed : minimumSilence)
                    ? TokenMonitorState.Down
                    : TokenMonitorState.Up;

                if (monitor.ApplyState(state, now))
                {
                    var alert = new TokenAccessAlert(
                        Guid.NewGuid(), monitor.TenantId, monitor.TokenId,
                        state == TokenMonitorState.Down
                            ? TokenAccessAlertKind.HeartbeatMissed
                            : TokenAccessAlertKind.HeartbeatRecovered,
                        ipAddress: null, now);

                    // A recovery is always visible in the statistics UI; the all-clear MAIL is per-monitor
                    // opt-out. Marking it emailed up front is how the shared mail poll skips it.
                    if (state == TokenMonitorState.Up && !monitor.NotifyOnRecovery)
                    {
                        alert.MarkEmailed(now);
                    }

                    db.TokenAccessAlerts.Add(alert);
                    logger.LogWarning(
                        "Heartbeat monitor for token {TokenId} transitioned to {State} (silence {SilenceMinutes} min, allowed {AllowedMinutes} min).",
                        monitor.TokenId, state, (long)silence.TotalMinutes, monitor.MaxSilenceMinutes);
                }

                if (monitor.LastEvaluatedAt is not { } stamped || now - stamped >= EvaluationStampInterval)
                {
                    monitor.MarkEvaluated(now);
                }
            }

            await db.SaveChangesAsync(ct).ConfigureAwait(false);

            if (databaseUnavailableLogged)
            {
                logger.LogInformation("Keyward database is reachable again — heartbeat monitoring resumed.");
                databaseUnavailableLogged = false;
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (DbException ex)
        {
            // Same posture as the ops monitor: one clear message, then quiet until the connection recovers.
            if (!databaseUnavailableLogged)
            {
                logger.LogWarning(ex,
                    "Heartbeat monitoring skipped — the Keyward database is unreachable. Monitors resume "
                    + "evaluating (without false alarms) once the connection recovers. This is logged once.");
                databaseUnavailableLogged = true;
            }
            else
            {
                logger.LogDebug(ex, "Heartbeat monitoring skipped again — database still unreachable.");
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Heartbeat monitor evaluation failed.");
        }
    }
}
