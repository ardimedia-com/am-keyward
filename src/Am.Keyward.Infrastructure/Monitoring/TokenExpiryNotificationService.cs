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
/// Finds app tokens nearing expiry on the <see cref="TokenExpiryNoticePolicy"/> schedule (30/20/10 days
/// ahead, then daily from 9 days) and hands them to <see cref="IKeywardAlertPresenter"/> for rendering and
/// delivery. Recipients are users who opted in on their profile AND administer the token's tenant (tenant
/// admins, or system admins).
/// <para>
/// Same split as <see cref="TokenAccessAlertNotificationService"/>, and for the same reason: this used to
/// live in the standalone shell, so an embedded Keyward silently let its tokens run out. The database work
/// ships with <c>AddKeyward</c>; identity, texts and transport stay with the host behind the port.
/// </para>
/// </summary>
public sealed class TokenExpiryNotificationService(
    IServiceScopeFactory scopeFactory,
    IClock clock,
    ILogger<TokenExpiryNotificationService> logger) : BackgroundService
{
    private static readonly TimeSpan CheckInterval = TimeSpan.FromHours(1);
    private static readonly TimeSpan StartupDelay = TimeSpan.FromMinutes(2);

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
                    await NotifyDueTokensAsync(stoppingToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Token-expiry notification run failed.");
                }
            }
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
            // Host shutting down — expected.
        }
    }

    private async Task NotifyDueTokensAsync(CancellationToken ct)
    {
        var now = clock.UtcNow;

        // The token table is installation-global (no tenant filter), so the discovery runs without a scope.
        using var scope = scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();

        var horizon = now.AddDays(TokenExpiryNoticePolicy.WindowDays + 1);
        var candidates = await db.SoftwareClientTokens
            .Where(t => t.RevokedAt == null && t.TokenHash != "" && t.ExpiresAt != null && t.ExpiresAt > now && t.ExpiresAt <= horizon)
            .ToListAsync(ct)
            .ConfigureAwait(false);

        var due = candidates
            .Select(t => (Token: t, DaysLeft: TokenExpiryNoticePolicy.DaysLeft(now, t.ExpiresAt!.Value)))
            .Where(x => TokenExpiryNoticePolicy.IsDue(x.DaysLeft, x.Token.LastExpiryNoticeDaysLeft))
            .ToList();
        if (due.Count == 0)
        {
            return;
        }

        // Without a presenter nobody would ever hear that a token is about to expire — say it once, loudly,
        // and leave the notices pending so they go out as soon as a host registers one.
        if (scope.ServiceProvider.GetService<IKeywardAlertPresenter>() is null)
        {
            if (!_missingPresenterLogged)
            {
                logger.LogError(
                    "{DueCount} app token(s) are nearing expiry but no {Port} is registered, so no notice is being sent. "
                    + "Register an implementation (the standalone shell uses branded mail; an embedding host should route "
                    + "onto its own notifications).",
                    due.Count, nameof(IKeywardAlertPresenter));
                _missingPresenterLogged = true;
            }

            return;
        }

        _missingPresenterLogged = false;

        // Per-tenant isolation AND per-tenant persistence: one failing tenant must neither skip the
        // remaining tenants nor lose the already-sent tenants' dedupe marks (which would re-send their
        // notices on the next run). The marks live on the discovery context's tracked entities (the token
        // table is installation-global, so this scope can write them).
        foreach (var tenantGroup in due.GroupBy(x => x.Token.TenantId))
        {
            var group = tenantGroup.ToList();
            try
            {
                if (await NotifyTenantAsync(tenantGroup.Key, group, ct).ConfigureAwait(false))
                {
                    foreach (var (token, daysLeft) in group)
                    {
                        token.MarkExpiryNoticeSent(daysLeft);
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
                logger.LogError(ex, "Token-expiry notification failed for tenant {TenantId}; continuing with the next tenant.", tenantGroup.Key);
            }
        }
    }

    private async Task<bool> NotifyTenantAsync(
        Guid tenantId, IReadOnlyList<(SoftwareClientToken Token, int DaysLeft)> due, CancellationToken ct)
    {
        // Per-tenant scope so the tenant-filtered tables (projects, environments) and row-level security
        // resolve — the token discovery above only touched the installation-global token table.
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
        var recipients = await db.Users
            .Where(u => u.NotifyTokenExpiry && u.Issuer == null && (u.IsSystemAdmin || adminUserIds.Contains(u.Id)))
            .Select(u => new KeywardAlertRecipient(u.Id, u.ExternalId))
            .ToListAsync(ct)
            .ConfigureAwait(false);
        if (recipients.Count == 0)
        {
            return false;
        }

        // Display data for the notification body (project + environment names).
        var projectNames = await db.Projects
            .Where(p => due.Select(d => d.Token.ProjectId).Contains(p.Id))
            .ToDictionaryAsync(p => p.Id, p => p.Name, ct)
            .ConfigureAwait(false);
        var environmentNames = await db.RuntimeEnvironments
            .Where(e => due.Select(d => d.Token.EnvironmentId).Contains(e.Id))
            .ToDictionaryAsync(e => e.Id, e => e.Name.Value, ct)
            .ConfigureAwait(false);

        var lines = due
            .OrderBy(x => x.DaysLeft)
            .Select(x => new KeywardTokenExpiryLine(
                x.Token.Name,
                projectNames.GetValueOrDefault(x.Token.ProjectId) ?? "?",
                environmentNames.GetValueOrDefault(x.Token.EnvironmentId) ?? "?",
                x.DaysLeft,
                x.Token.ExpiresAt!.Value))
            .ToList();

        var delivered = await presenter
            .NotifyTokenExpiryAsync(tenantId, recipients, lines, ct)
            .ConfigureAwait(false);
        if (delivered == 0)
        {
            return false;
        }

        logger.LogInformation(
            "Token-expiry notification delivered to {RecipientCount} recipient(s) for tenant {TenantId} covering {TokenCount} token(s).",
            delivered, tenantId, due.Count);
        return true;
    }
}
