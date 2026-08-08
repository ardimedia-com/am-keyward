using System.Globalization;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain.Software;
using Am.Keyward.Ui.Blazor;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Localization;

namespace Am.Keyward.Ui.Blazor.App.Identity;

/// <summary>
/// The standalone shell's <see cref="IKeywardAlertPresenter"/>: renders the alerts as a branded card and
/// mails them, one message per recipient and category. This is the presentation half of what used to be
/// <c>TokenAccessAlertEmailService</c>; the database work now lives in
/// <c>Am.Keyward.Infrastructure.Monitoring.TokenAccessAlertNotificationService</c>, which ships with
/// <c>AddKeyward</c> so an embedded Keyward gets the alerts too.
/// <para>
/// Resolving a Keyward user's mailbox is exactly why this side belongs to the host: the mapping runs through
/// ASP.NET Identity, which the infrastructure layer neither has nor should acquire.
/// </para>
/// </summary>
public sealed class BrandedMailAlertPresenter(
    UserManager<IdentityUser> identityUsers,
    IAccountEmailSender sender,
    IStringLocalizer<SharedResource> loc,
    KeywardUiOptions uiOptions,
    ILogger<BrandedMailAlertPresenter> logger) : IKeywardAlertPresenter
{
    public async Task<int> NotifyTokenAlertsAsync(
        Guid tenantId,
        bool monitoring,
        IReadOnlyList<KeywardAlertRecipient> recipients,
        IReadOnlyList<KeywardTokenAlertLine> lines,
        CancellationToken ct = default)
    {
        var (subject, content) = BuildContent(monitoring, lines);
        return await SendAsync(recipients, subject, content, ct).ConfigureAwait(false);
    }

    public async Task<int> NotifyTokenExpiryAsync(
        Guid tenantId,
        IReadOnlyList<KeywardAlertRecipient> recipients,
        IReadOnlyList<KeywardTokenExpiryLine> lines,
        CancellationToken ct = default)
    {
        var (subject, content) = BuildExpiryContent(lines);
        return await SendAsync(recipients, subject, content, ct).ConfigureAwait(false);
    }

    private async Task<int> SendAsync(
        IReadOnlyList<KeywardAlertRecipient> recipients, string subject, BrandedEmailContent content, CancellationToken ct)
    {
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
                logger.LogError(ex, "Failed to send the Keyward alert notification to {Email}.", email);
            }
        }

        return sent;
    }

    private (string Subject, BrandedEmailContent Content) BuildExpiryContent(IReadOnlyList<KeywardTokenExpiryLine> due)
    {
        // With a configured public base URL the mail carries a button to the Applications page (its
        // «Client-Tokens» tab holds the tokens); without one it stays a plain notification.
        var tokensUrl = string.IsNullOrWhiteSpace(uiOptions.PublicBaseUrl)
            ? null
            : uiOptions.PublicBaseUrl.TrimEnd('/') + KeywardRoutes.Applications;

        var previous = CultureInfo.CurrentUICulture;
        CultureInfo.CurrentUICulture = ResolveNotificationCulture();
        try
        {
            var lines = due
                .Select(x => loc[
                    "Email.TokenExpiry.Line",
                    x.TokenName,
                    x.ProjectName,
                    x.EnvironmentName,
                    x.DaysLeft,
                    x.ExpiresAt.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)].Value)
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

    private (string Subject, BrandedEmailContent Content) BuildContent(bool monitoring, IReadOnlyList<KeywardTokenAlertLine> alerts)
    {
        var tokensUrl = string.IsNullOrWhiteSpace(uiOptions.PublicBaseUrl)
            ? null
            : uiOptions.PublicBaseUrl.TrimEnd('/') + KeywardRoutes.Applications;

        // Outside any request there is no request culture — build the whole message under the configured
        // notification language (English fallback); all localizer lookups happen before the first await.
        var previous = CultureInfo.CurrentUICulture;
        CultureInfo.CurrentUICulture = ResolveNotificationCulture();
        try
        {
            var prefix = monitoring ? "Email.Monitor" : "Email.TokenAccess";
            var lines = alerts
                .Select(a =>
                {
                    var key = a.Kind switch
                    {
                        TokenAccessAlertKind.NewIpAddress => "Email.TokenAccess.Line.NewIp",
                        TokenAccessAlertKind.ResumedAfterSilence => "Email.TokenAccess.Line.Resumed",
                        TokenAccessAlertKind.HeartbeatMissed => "Email.Monitor.Line.Missed",
                        _ => "Email.Monitor.Line.Recovered",
                    };
                    return loc[
                        key,
                        a.TokenName,
                        a.ProjectName,
                        a.EnvironmentName,
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
