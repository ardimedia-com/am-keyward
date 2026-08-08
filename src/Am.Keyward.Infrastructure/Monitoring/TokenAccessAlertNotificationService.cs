using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Software;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Am.Keyward.Infrastructure.Monitoring;

/// <summary>
/// Picks up the alerts the statistics flush and the heartbeat monitor record, works out who should hear
/// about them, and hands them to <see cref="IKeywardAlertPresenter"/> for rendering and delivery.
/// <para>
/// This half deliberately holds no identity, no texts and no transport — only the database work: which
/// alerts are still pending, which opted-in administrators cover the tenant, the display names for the
/// lines, and the dedupe mark afterwards. That split is what lets the poller ship with <c>AddKeyward</c>
/// and run in ANY host. Until 2026-08-07 the whole thing lived in the standalone shell, so an embedded
/// Keyward detected outages and then discarded the alarm without a trace (found via a missed
/// UpdateAdUsers heartbeat in bvd.li.toolbox).
/// </para>
/// <para>
/// Best-effort throughout: a failing tenant never blocks the others, and nothing here may crash the host.
/// </para>
/// </summary>
public sealed class TokenAccessAlertNotificationService(
    IServiceScopeFactory scopeFactory,
    IClock clock,
    ILogger<TokenAccessAlertNotificationService> logger) : BackgroundService
{
    private static readonly TimeSpan CheckInterval = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan StartupDelay = TimeSpan.FromMinutes(2);

    /// <summary>
    /// Only alerts from this window are delivered, so an installation without opted-in administrators does
    /// not accumulate an unbounded backlog. Older ones stay visible in the statistics tab regardless.
    /// </summary>
    private static readonly TimeSpan MailableWindow = TimeSpan.FromDays(7);

    private bool _missingPresenterLogged;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await Task.Delay(StartupDelay, stoppingToken).ConfigureAwait(false);
            using var timer = new PeriodicTimer(CheckInterval);
            do
            {
                try
                {
                    await NotifyFreshAlertsAsync(stoppingToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Token alert notification run failed.");
                }
            }
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
            // Host shutting down — expected.
        }
    }

    private async Task NotifyFreshAlertsAsync(CancellationToken ct)
    {
        var now = clock.UtcNow;

        // The alert table is installation-global (like the token table), so discovery runs without a scope.
        using var scope = scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();

        var horizon = now - MailableWindow;
        var due = await db.TokenAccessAlerts
            .Where(a => a.EmailedAt == null && a.CreatedAt > horizon)
            .OrderBy(a => a.CreatedAt)
            .ToListAsync(ct)
            .ConfigureAwait(false);
        if (due.Count == 0)
        {
            return;
        }

        // A host that never registered a presenter would otherwise drop every alert silently — exactly the
        // failure this service exists to end. Say it once per process, at Error, and keep the alerts pending.
        if (scope.ServiceProvider.GetService<IKeywardAlertPresenter>() is null)
        {
            if (!_missingPresenterLogged)
            {
                logger.LogError(
                    "{PendingCount} Keyward alert(s) are waiting to be delivered but no {Port} is registered, so nobody is "
                    + "being notified. Register an implementation (the standalone shell uses branded mail; an embedding host "
                    + "should route onto its own notifications). The alerts stay pending and are delivered once one exists.",
                    due.Count, nameof(IKeywardAlertPresenter));
                _missingPresenterLogged = true;
            }

            return;
        }

        _missingPresenterLogged = false;

        // Two categories with separate opt-ins and texts; each is grouped per tenant below.
        (List<TokenAccessAlert> Alerts, bool Monitoring)[] categories =
        [
            (due.Where(a => a.Kind is TokenAccessAlertKind.NewIpAddress or TokenAccessAlertKind.ResumedAfterSilence).ToList(), false),
            (due.Where(a => a.Kind is TokenAccessAlertKind.HeartbeatMissed or TokenAccessAlertKind.HeartbeatRecovered).ToList(), true),
        ];

        // Per-tenant isolation AND per-tenant persistence — one failing tenant must neither skip the rest
        // nor lose the already-delivered tenants' dedupe marks (the marks live on this context's tracked rows).
        foreach (var (alerts, monitoring) in categories)
        {
            foreach (var tenantGroup in alerts.GroupBy(a => a.TenantId))
            {
                var group = tenantGroup.ToList();
                try
                {
                    if (await NotifyTenantAsync(tenantGroup.Key, group, monitoring, ct).ConfigureAwait(false))
                    {
                        foreach (var alert in group)
                        {
                            alert.MarkEmailed(now);
                        }

                        await db.SaveChangesAsync(ct).ConfigureAwait(false);
                    }
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Token alert notification failed for tenant {TenantId}; continuing with the next tenant.", tenantGroup.Key);
                }
            }
        }
    }

    private async Task<bool> NotifyTenantAsync(Guid tenantId, IReadOnlyList<TokenAccessAlert> alerts, bool monitoring, CancellationToken ct)
    {
        // Per-tenant scope so the tenant-filtered tables (projects, environments) resolve; the alert/token
        // discovery above only touched installation-global tables.
        using var scope = scopeFactory.CreateScope();
        scope.ServiceProvider.GetRequiredService<ITenantScopeSetter>().SetTenant(tenantId);
        var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
        var presenter = scope.ServiceProvider.GetRequiredService<IKeywardAlertPresenter>();

        // Opted-in users who administer this tenant (its tenant admins, or installation system admins).
        var adminUserIds = await db.TenantMemberships
            .Where(m => m.TenantId == tenantId && m.Role == TenantRole.TenantAdmin)
            .Select(m => m.UserId)
            .ToListAsync(ct)
            .ConfigureAwait(false);
        // A host with its own subscription model gets every administrator and decides itself who to tell;
        // otherwise Keyward's per-user opt-ins select the audience. See IKeywardAlertPresenter.
        var recipients = await db.Users
            .Where(u => (presenter.OwnsRecipientSelection || (monitoring ? u.NotifyMonitoring : u.NotifyTokenAccessAlerts))
                && u.Issuer == null && (u.IsSystemAdmin || adminUserIds.Contains(u.Id)))
            .Select(u => new KeywardAlertRecipient(u.Id, u.ExternalId))
            .ToListAsync(ct)
            .ConfigureAwait(false);
        if (recipients.Count == 0)
        {
            return false;
        }

        // Display data for the notification body (token, project and environment names).
        var tokenIds = alerts.Select(a => a.TokenId).Distinct().ToList();
        var tokens = await db.SoftwareClientTokens
            .Where(t => tokenIds.Contains(t.Id))
            .ToDictionaryAsync(t => t.Id, ct)
            .ConfigureAwait(false);
        var projectIds = tokens.Values.Select(t => t.ProjectId).Distinct().ToList();
        var projectNames = await db.Projects
            .Where(p => projectIds.Contains(p.Id))
            .ToDictionaryAsync(p => p.Id, p => p.Name, ct)
            .ConfigureAwait(false);
        var environmentIds = tokens.Values.Select(t => t.EnvironmentId).Distinct().ToList();
        var environmentNames = await db.RuntimeEnvironments
            .Where(e => environmentIds.Contains(e.Id))
            .ToDictionaryAsync(e => e.Id, e => e.Name.Value, ct)
            .ConfigureAwait(false);

        var lines = alerts
            .Select(a =>
            {
                var token = tokens.GetValueOrDefault(a.TokenId);
                return new KeywardTokenAlertLine(
                    a.Kind,
                    token?.Name ?? "?",
                    token is null ? "?" : projectNames.GetValueOrDefault(token.ProjectId) ?? "?",
                    token is null ? "?" : environmentNames.GetValueOrDefault(token.EnvironmentId) ?? "?",
                    a.IpAddress,
                    a.CreatedAt);
            })
            .ToList();

        var delivered = await presenter
            .NotifyTokenAlertsAsync(tenantId, monitoring, recipients, lines, ct)
            .ConfigureAwait(false);
        if (delivered == 0)
        {
            return false;
        }

        logger.LogInformation(
            "Token alert notification delivered to {RecipientCount} recipient(s) for tenant {TenantId} covering {AlertCount} alert(s).",
            delivered, tenantId, alerts.Count);
        return true;
    }
}
