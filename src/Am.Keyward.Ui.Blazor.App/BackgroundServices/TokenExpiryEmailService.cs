using System.Globalization;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Infrastructure.Persistence;
using Am.Keyward.Ui.Blazor;
using Am.Keyward.Ui.Blazor.App.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Localization;

namespace Am.Keyward.Ui.Blazor.App.BackgroundServices;

/// <summary>
/// E-mails administrators about app tokens nearing expiry, on the <see cref="TokenExpiryNoticePolicy"/>
/// schedule (30/20/10 days ahead, then daily from 9 days). Recipients are users who opted in on their
/// profile AND administer the token's tenant (tenant admins, or system admins). One mail per recipient and
/// run, listing all due tokens; a token is marked notified only after at least one mail went out, so a
/// notice is not lost while nobody has opted in yet. Best-effort: failures are logged, never crash the host.
/// </summary>
public sealed class TokenExpiryEmailService(
    IServiceScopeFactory scopeFactory,
    IClock clock,
    KeywardUiOptions uiOptions,
    ILogger<TokenExpiryEmailService> logger) : BackgroundService
{
    private static readonly TimeSpan CheckInterval = TimeSpan.FromHours(1);
    private static readonly TimeSpan StartupDelay = TimeSpan.FromMinutes(2);

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

        // Per-tenant isolation AND per-tenant persistence: one failing tenant must neither skip the
        // remaining tenants nor lose the already-sent tenants' dedupe marks (which would re-send their
        // mails on the next run). The marks live on the discovery context's tracked entities (the token
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
        Guid tenantId, IReadOnlyList<(Core.Domain.Software.SoftwareClientToken Token, int DaysLeft)> due, CancellationToken ct)
    {
        // Per-tenant scope so the tenant-filtered tables (projects, environments) and row-level security
        // resolve — the token discovery above only touched the installation-global token table.
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
            .Where(u => u.NotifyTokenExpiry && u.Issuer == null && (u.IsSystemAdmin || adminUserIds.Contains(u.Id)))
            .ToListAsync(ct)
            .ConfigureAwait(false);
        if (recipients.Count == 0)
        {
            return false;
        }

        // Display data for the mail body (project + environment names).
        var projectNames = await db.Projects
            .Where(p => due.Select(d => d.Token.ProjectId).Contains(p.Id))
            .ToDictionaryAsync(p => p.Id, p => p.Name, ct)
            .ConfigureAwait(false);
        var environmentNames = await db.RuntimeEnvironments
            .Where(e => due.Select(d => d.Token.EnvironmentId).Contains(e.Id))
            .ToDictionaryAsync(e => e.Id, e => e.Name.Value, ct)
            .ConfigureAwait(false);

        // With a configured public base URL the mail carries a button straight to the app-tokens page;
        // without one it stays a plain notification.
        var tokensUrl = string.IsNullOrWhiteSpace(uiOptions.PublicBaseUrl)
            ? null
            : uiOptions.PublicBaseUrl.TrimEnd('/') + KeywardRoutes.ClientTokens;

        // This runs outside any request, so there is no request culture to follow — build the whole
        // message under the configured notification language (English fallback). All localizer lookups are
        // synchronous, so the culture is restored before the first await (the send loop).
        var (subject, content) = BuildContent();

        (string Subject, BrandedEmailContent Content) BuildContent()
        {
            var previous = CultureInfo.CurrentUICulture;
            CultureInfo.CurrentUICulture = ResolveNotificationCulture();
            try
            {
                var lines = due
                    .OrderBy(x => x.DaysLeft)
                    .Select(x => loc[
                        "Email.TokenExpiry.Line",
                        x.Token.Name,
                        projectNames.GetValueOrDefault(x.Token.ProjectId, "?"),
                        environmentNames.GetValueOrDefault(x.Token.EnvironmentId, "?"),
                        x.DaysLeft,
                        x.Token.ExpiresAt!.Value.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)].Value)
                    .ToList();

                return (loc["Email.TokenExpiry.Subject", uiOptions.ProductName].Value, new BrandedEmailContent
                {
                    Brand = uiOptions.ProductName,
                    Title = loc["Email.TokenExpiry.Title"].Value,
                    Paragraphs =
                    [
                        loc["Email.TokenExpiry.Intro"].Value,
                        .. lines,
                        loc["Email.TokenExpiry.Outro"].Value,
                    ],
                    ButtonText = tokensUrl is null ? null : loc["Email.TokenExpiry.Button"].Value,
                    ActionUrl = tokensUrl,
                    FooterNote = loc["Email.TokenExpiry.Footer"].Value,
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
                logger.LogError(ex, "Failed to send the token-expiry notification to {Email}.", email);
            }
        }

        if (sent == 0)
        {
            return false;
        }

        logger.LogInformation(
            "Token-expiry notification sent to {RecipientCount} recipient(s) for tenant {TenantId} covering {TokenCount} token(s).",
            sent, tenantId, due.Count);
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
