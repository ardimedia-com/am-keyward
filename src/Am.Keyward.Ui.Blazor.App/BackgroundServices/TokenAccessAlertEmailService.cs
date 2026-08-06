using System.Globalization;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Software;
using Am.Keyward.Infrastructure.Persistence;
using Am.Keyward.Ui.Blazor;
using Am.Keyward.Ui.Blazor.App.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Localization;

namespace Am.Keyward.Ui.Blazor.App.BackgroundServices;

/// <summary>
/// E-mails administrators about token alerts: the access-pattern kinds the statistics flush derives (a
/// token used from a never-seen IP, or active again after a long silence) and the heartbeat-monitoring
/// kinds the monitor evaluator derives (a monitored token silent past its deadline, or recovered). The two
/// categories go to separate opt-ins (<c>NotifyTokenAccessAlerts</c> vs <c>NotifyMonitoring</c> — different
/// audience and frequency) as separate mails, but share the recipient model (opted in AND administering
/// the token's tenant: tenant admins, or system admins — same as <see cref="TokenExpiryEmailService"/>).
/// One mail per recipient, category and run, listing that tenant's fresh alerts; an alert is marked
/// e-mailed only after at least one mail went out, and only alerts from the last
/// <see cref="MailableWindow"/> are considered so an installation without opted-in admins does not
/// accumulate an unbounded backlog (older alerts stay visible in the statistics tab regardless).
/// Best-effort: failures are logged, never crash the host.
/// </summary>
public sealed class TokenAccessAlertEmailService(
    IServiceScopeFactory scopeFactory,
    IClock clock,
    KeywardUiOptions uiOptions,
    ILogger<TokenAccessAlertEmailService> logger) : BackgroundService
{
    private static readonly TimeSpan CheckInterval = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan StartupDelay = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan MailableWindow = TimeSpan.FromDays(7);

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
                    logger.LogError(ex, "Token access-alert notification run failed.");
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

        // Two mail categories with separate opt-ins and texts; each is grouped per tenant below.
        (List<TokenAccessAlert> Alerts, bool Monitoring)[] categories =
        [
            (due.Where(a => a.Kind is TokenAccessAlertKind.NewIpAddress or TokenAccessAlertKind.ResumedAfterSilence).ToList(), false),
            (due.Where(a => a.Kind is TokenAccessAlertKind.HeartbeatMissed or TokenAccessAlertKind.HeartbeatRecovered).ToList(), true),
        ];

        // Per-tenant isolation AND per-tenant persistence — one failing tenant must neither skip the rest
        // nor lose the already-sent tenants' dedupe marks (the marks live on this context's tracked rows).
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
                    logger.LogError(ex, "Token access-alert notification failed for tenant {TenantId}; continuing with the next tenant.", tenantGroup.Key);
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
        var identityUsers = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
        var loc = scope.ServiceProvider.GetRequiredService<IStringLocalizer<SharedResource>>();

        // Opted-in users who administer this tenant (its tenant admins, or installation system admins).
        var adminUserIds = await db.TenantMemberships
            .Where(m => m.TenantId == tenantId && m.Role == TenantRole.TenantAdmin)
            .Select(m => m.UserId)
            .ToListAsync(ct)
            .ConfigureAwait(false);
        var recipients = await db.Users
            .Where(u => (monitoring ? u.NotifyMonitoring : u.NotifyTokenAccessAlerts)
                && u.Issuer == null && (u.IsSystemAdmin || adminUserIds.Contains(u.Id)))
            .ToListAsync(ct)
            .ConfigureAwait(false);
        if (recipients.Count == 0)
        {
            return false;
        }

        // Display data for the mail body (token, project and environment names).
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

        var tokensUrl = string.IsNullOrWhiteSpace(uiOptions.PublicBaseUrl)
            ? null
            : uiOptions.PublicBaseUrl.TrimEnd('/') + KeywardRoutes.Applications;

        // Outside any request there is no request culture — build the whole message under the configured
        // notification language (English fallback); all localizer lookups happen before the first await.
        var (subject, content) = BuildContent();

        (string Subject, BrandedEmailContent Content) BuildContent()
        {
            var previous = CultureInfo.CurrentUICulture;
            CultureInfo.CurrentUICulture = ResolveNotificationCulture();
            try
            {
                var prefix = monitoring ? "Email.Monitor" : "Email.TokenAccess";
                var lines = alerts
                    .Select(a =>
                    {
                        var token = tokens.GetValueOrDefault(a.TokenId);
                        var key = a.Kind switch
                        {
                            TokenAccessAlertKind.NewIpAddress => "Email.TokenAccess.Line.NewIp",
                            TokenAccessAlertKind.ResumedAfterSilence => "Email.TokenAccess.Line.Resumed",
                            TokenAccessAlertKind.HeartbeatMissed => "Email.Monitor.Line.Missed",
                            _ => "Email.Monitor.Line.Recovered",
                        };
                        return loc[
                            key,
                            token?.Name ?? "?",
                            token is null ? "?" : projectNames.GetValueOrDefault(token.ProjectId, "?"),
                            token is null ? "?" : environmentNames.GetValueOrDefault(token.EnvironmentId, "?"),
                            a.IpAddress ?? "?",
                            a.CreatedAt.UtcDateTime.ToString("yyyy-MM-dd HH:mm 'UTC'", CultureInfo.InvariantCulture)].Value;
                    })
                    .ToList();

                return (loc[prefix + ".Subject", uiOptions.ProductName].Value, new BrandedEmailContent
                {
                    Brand = uiOptions.ProductName,
                    Title = loc[prefix + ".Title"].Value,
                    Paragraphs =
                    [
                        loc[prefix + ".Intro"].Value,
                        .. lines,
                        loc[prefix + ".Outro"].Value,
                    ],
                    ButtonText = tokensUrl is null ? null : loc[prefix + ".Button"].Value,
                    ActionUrl = tokensUrl,
                    FooterNote = loc[prefix + ".Footer"].Value,
                });
            }
            finally
            {
                CultureInfo.CurrentUICulture = previous;
            }
        }

        var sender = scope.ServiceProvider.GetRequiredService<IAccountEmailSender>();
        var sent = 0;
        foreach (var recipient in recipients)
        {
            var identityUser = await identityUsers.FindByIdAsync(recipient.ExternalId).ConfigureAwait(false);
            if (identityUser?.Email is not { Length: > 0 } email)
            {
                continue;
            }

            try
            {
                await sender.SendAsync(email, subject, content, ct).ConfigureAwait(false);
                sent++;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to send the token access-alert notification to {Email}.", email);
            }
        }

        if (sent == 0)
        {
            return false;
        }

        logger.LogInformation(
            "Token access-alert notification sent to {RecipientCount} recipient(s) for tenant {TenantId} covering {AlertCount} alert(s).",
            sent, tenantId, alerts.Count);
        return true;
    }

    private CultureInfo ResolveNotificationCulture()
    {
        if (!string.IsNullOrWhiteSpace(uiOptions.NotificationLanguage))
        {
            try { return CultureInfo.GetCultureInfo(uiOptions.NotificationLanguage); }
            catch (CultureNotFoundException)
            {
                logger.LogWarning("Configured notification language '{Language}' is not a valid culture; falling back to English.", uiOptions.NotificationLanguage);
            }
        }

        return CultureInfo.GetCultureInfo("en");
    }
}
