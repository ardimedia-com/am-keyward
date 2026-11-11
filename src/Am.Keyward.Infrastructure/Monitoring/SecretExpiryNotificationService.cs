using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Software;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Am.Keyward.Infrastructure.Monitoring;

/// <summary>
/// Finds software-secret VALUES nearing their rotation date on the <see cref="ExpiryNoticePolicy"/> schedule
/// — the same 30/20/10-days-then-daily rhythm as app tokens — and hands them to
/// <see cref="IKeywardAlertPresenter"/> for rendering and delivery. Recipients are the users who opted into
/// expiry notices AND administer the owning tenant.
/// <para>
/// Unlike a token expiry, a secret-value expiry is ADVISORY: nothing stops working when the date passes (a
/// forgotten rotation must never take a deployed application down), so this notice is the only thing that
/// makes the date matter. Each line carries the value's rotation note, because "how do I get a new one" is
/// exactly the question the notice raises. The secret itself never leaves the database here. Because nothing stops
/// working, the date passing is announced ONCE more («expired», days left 0 or below) — otherwise a missed rotation
/// would go quiet exactly when it matters. Dates that passed more than <see cref="OverdueWindow"/> ago are left alone,
/// so an upgrade does not mail a backlog of long-forgotten values.
/// </para>
/// <para>
/// Structural difference to <see cref="TokenExpiryNotificationService"/>: the token table is
/// installation-global, so it can be discovered in one tenant-less query. <c>SecretValues</c> is tenant-scoped
/// by BOTH the EF query filter and SQL Server row-level security, so discovery runs PER TENANT (the tenant
/// list comes from the membership table, which is installation-global). That also keeps the dedupe UPDATE
/// inside the tenant's own scope, where the RLS block predicate admits it.
/// </para>
/// </summary>
public sealed class SecretExpiryNotificationService(
    IServiceScopeFactory scopeFactory,
    IClock clock,
    IOptions<MonitoringOptions> monitoringOptions,
    ILogger<SecretExpiryNotificationService> logger) : BackgroundService
{
    private static readonly TimeSpan CheckInterval = TimeSpan.FromHours(1);

    // Offset against the token service's two minutes: both wake on the same interval, and there is no reason
    // for them to hit the database in the same instant on every tick.
    private static readonly TimeSpan StartupDelay = TimeSpan.FromMinutes(3);

    /// <summary>How long after its date a value still gets its one «expired» notice.</summary>
    internal static readonly TimeSpan OverdueWindow = TimeSpan.FromDays(30);

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
                    await NotifyDueValuesAsync(stoppingToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Secret-expiry notification run failed.");
                }
            }
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
            // Host shutting down — expected.
        }
    }

    /// <summary>One run over every tenant. Returns how many values were marked announced.</summary>
    internal async Task<int> NotifyDueValuesAsync(CancellationToken ct)
    {
        List<Guid> tenantIds;
        bool hasPresenter;
        using (var discoveryScope = scopeFactory.CreateScope())
        {
            // The membership table is installation-global, so this runs without a tenant scope. A tenant with
            // no members has nobody to notify anyway, which is exactly who this list leaves out.
            var db = discoveryScope.ServiceProvider.GetRequiredService<KeywardDbContext>();
            tenantIds = await db.TenantMemberships
                .Select(m => m.TenantId)
                .Distinct()
                .ToListAsync(ct)
                .ConfigureAwait(false);
            hasPresenter = discoveryScope.ServiceProvider.GetService<IKeywardAlertPresenter>() is not null;
        }

        if (tenantIds.Count == 0)
        {
            return 0;
        }

        var marked = 0;
        foreach (var tenantId in tenantIds)
        {
            try
            {
                marked += await NotifyTenantAsync(tenantId, hasPresenter, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Secret-expiry notification failed for tenant {TenantId}; continuing with the next tenant.", tenantId);
            }
        }

        return marked;
    }

    private async Task<int> NotifyTenantAsync(Guid tenantId, bool hasPresenter, CancellationToken ct)
    {
        var now = clock.UtcNow;
        var zone = monitoringOptions.Value.ResolveTimeZone(logger);
        using var scope = scopeFactory.CreateScope();
        scope.ServiceProvider.GetRequiredService<ITenantScopeSetter>().SetTenant(tenantId);
        var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();

        var horizon = now.AddDays(ExpiryNoticePolicy.WindowDays + 1);
        var overdueHorizon = now - OverdueWindow;
        var candidates = await db.SecretValues
            .Where(v => v.ExpiresAt != null && v.ExpiresAt > overdueHorizon && v.ExpiresAt <= horizon)
            .ToListAsync(ct)
            .ConfigureAwait(false);

        // Ahead of the date: the 30/20/10-then-daily schedule (calendar days in the installation's zone). Past it: one
        // «expired» notice, recorded as ExpiryNoticePolicy.OverdueNoticeMarker.
        var due = candidates
            .Select(v => (Value: v, DaysLeft: ExpiryNoticePolicy.DaysLeft(now, v.ExpiresAt!.Value, zone)))
            .Where(x => ExpiryNoticePolicy.IsDue(x.DaysLeft, x.Value.LastExpiryNoticeDaysLeft)
                || ExpiryNoticePolicy.IsOverdueNoticeDue(x.DaysLeft, x.Value.LastExpiryNoticeDaysLeft))
            .ToList();
        if (due.Count == 0)
        {
            return 0;
        }

        // Without a presenter nobody would ever hear that a value is due for rotation — say it once, loudly,
        // and leave the notices pending so they go out as soon as a host registers one.
        if (!hasPresenter)
        {
            if (!_missingPresenterLogged)
            {
                logger.LogError(
                    "{DueCount} software-secret value(s) are nearing their rotation date but no {Port} is registered, so no "
                    + "notice is being sent. Register an implementation (the standalone shell uses branded mail; an embedding "
                    + "host should route onto its own notifications).",
                    due.Count, nameof(IKeywardAlertPresenter));
                _missingPresenterLogged = true;
            }

            return 0;
        }

        _missingPresenterLogged = false;

        var presenter = scope.ServiceProvider.GetRequiredService<IKeywardAlertPresenter>();

        // Opted-in users who administer this tenant (its tenant admins, or installation system admins).
        var adminUserIds = await db.TenantMemberships
            .Where(m => m.TenantId == tenantId && m.Role == TenantRole.TenantAdmin)
            .Select(m => m.UserId)
            .ToListAsync(ct)
            .ConfigureAwait(false);
        // A host with its own subscription model gets every administrator and decides itself who to tell;
        // otherwise Keyward's per-user opt-in selects the audience. See IKeywardAlertPresenter.
        var recipients = await db.Users
            .Where(u => (presenter.OwnsRecipientSelection || u.NotifyExpiry)
                && u.Issuer == null && (u.IsSystemAdmin || adminUserIds.Contains(u.Id)))
            .Select(u => new KeywardAlertRecipient(u.Id, u.ExternalId))
            .ToListAsync(ct)
            .ConfigureAwait(false);
        if (recipients.Count == 0)
        {
            return 0;
        }

        var lines = await BuildLinesAsync(db, due, ct).ConfigureAwait(false);
        var delivered = await presenter.NotifySecretExpiryAsync(tenantId, recipients, lines, ct).ConfigureAwait(false);
        if (delivered == 0)
        {
            return 0;
        }

        // Only now is the notice recorded: a host that could not deliver keeps them pending instead of
        // losing them. The UPDATE runs in the tenant's own scope, so RLS admits it.
        // One SaveChanges for the whole tenant on this scope's own context, so the change-tracker reset after a save
        // cannot drop marks of a later group (the failure mode of the other notice jobs before review 3).
        foreach (var (value, daysLeft) in due)
        {
            value.MarkExpiryNoticeSent(daysLeft < 1 ? ExpiryNoticePolicy.OverdueNoticeMarker : daysLeft);
        }

        await db.SaveChangesAsync(ct).ConfigureAwait(false);

        logger.LogInformation(
            "Secret-expiry notification delivered to {RecipientCount} recipient(s) for tenant {TenantId} covering {ValueCount} value(s).",
            delivered, tenantId, due.Count);
        return due.Count;
    }

    /// <summary>Resolves the display data for the notice body (secret key, application and environment names).</summary>
    private static async Task<IReadOnlyList<KeywardSecretExpiryLine>> BuildLinesAsync(
        KeywardDbContext db, IReadOnlyList<(SecretValue Value, int DaysLeft)> due, CancellationToken ct)
    {
        var secretIds = due.Select(d => d.Value.SoftwareSecretId).Distinct().ToList();
        var secrets = await db.SoftwareSecrets
            .Where(s => secretIds.Contains(s.Id))
            .Select(s => new { s.Id, s.Key, s.ProjectId })
            .ToListAsync(ct)
            .ConfigureAwait(false);
        var secretsById = secrets.ToDictionary(s => s.Id);

        var projectIds = secrets.Select(s => s.ProjectId).Distinct().ToList();
        var projectNames = await db.Projects
            .Where(p => projectIds.Contains(p.Id))
            .ToDictionaryAsync(p => p.Id, p => p.Name, ct)
            .ConfigureAwait(false);

        var environmentIds = due.Select(d => d.Value.EnvironmentId).Distinct().ToList();
        var environmentNames = await db.RuntimeEnvironments
            .Where(e => environmentIds.Contains(e.Id))
            .ToDictionaryAsync(e => e.Id, e => e.Name.Value, ct)
            .ConfigureAwait(false);

        return due
            .OrderBy(x => x.DaysLeft)
            .Select(x =>
            {
                var secret = secretsById.GetValueOrDefault(x.Value.SoftwareSecretId);
                return new KeywardSecretExpiryLine(
                    secret?.Key.Value ?? "?",
                    secret is null ? "?" : projectNames.GetValueOrDefault(secret.ProjectId) ?? "?",
                    environmentNames.GetValueOrDefault(x.Value.EnvironmentId) ?? "?",
                    x.DaysLeft,
                    x.Value.ExpiresAt!.Value,
                    x.Value.Note);
            })
            .ToList();
    }
}
