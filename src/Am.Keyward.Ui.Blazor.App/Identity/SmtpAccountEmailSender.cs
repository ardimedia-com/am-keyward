using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Options;
using MimeKit;

namespace Am.Keyward.Ui.Blazor.App.Identity;

/// <summary>
/// Sends account e-mails (password reset, e-mail confirmation) over SMTP via MailKit. Selected instead of the
/// maildrop sender when <c>AccountEmail:Smtp:Host</c> is configured (e.g. the LAN relay <c>smtptest.ardimedia.com</c>
/// in development — see smtp-relay-hosts.md). The single-use link is never logged; only that a mail was sent.
/// </summary>
public sealed class SmtpAccountEmailSender(
    IOptions<AccountEmailOptions> options,
    Am.Keyward.Ui.Blazor.KeywardUiOptions uiOptions,
    ILogger<SmtpAccountEmailSender> logger) : IAccountEmailSender
{
    public Task SendPasswordResetLinkAsync(string email, string resetLink, CancellationToken ct = default)
    {
        var (subject, content) = AccountEmailMessages.PasswordReset(resetLink, uiOptions.ProductName);
        return SendAsync(email, subject, content, ct);
    }

    public Task SendEmailConfirmationLinkAsync(string email, string confirmLink, CancellationToken ct = default)
    {
        var (subject, content) = AccountEmailMessages.EmailConfirmation(confirmLink, uiOptions.ProductName);
        return SendAsync(email, subject, content, ct);
    }

    public async Task SendAsync(string to, string subject, BrandedEmailContent content, CancellationToken ct = default)
    {
        var smtp = options.Value.Smtp;
        // This sender is only registered when a host is configured (see Program.cs), so this never trips.
        var host = smtp.Host ?? throw new InvalidOperationException("AccountEmail:Smtp:Host is not configured.");

        var message = new MimeMessage();
        message.From.Add(MailboxAddress.Parse(smtp.From));
        message.To.Add(MailboxAddress.Parse(to));
        message.Subject = subject;
        // multipart/alternative: branded HTML card + plain-text fallback, from one source (BrandedEmail).
        message.Body = new BodyBuilder
        {
            HtmlBody = BrandedEmail.RenderHtml(content),
            TextBody = BrandedEmail.RenderText(content),
        }.ToMessageBody();

        using var client = new SmtpClient();
        // Auto negotiates STARTTLS when the relay offers it and falls back to plaintext for an internal relay
        // that does not (e.g. an unauthenticated LAN relay on port 25).
        await client.ConnectAsync(host, smtp.Port, SecureSocketOptions.Auto, ct).ConfigureAwait(false);
        if (!string.IsNullOrEmpty(smtp.User))
        {
            await client.AuthenticateAsync(smtp.User, smtp.Password ?? string.Empty, ct).ConfigureAwait(false);
        }

        await client.SendAsync(message, ct).ConfigureAwait(false);
        await client.DisconnectAsync(quit: true, ct).ConfigureAwait(false);

        // Do NOT log the link/token (single-use secret) — only that a mail was sent.
        logger.LogInformation("Account e-mail sent via SMTP {Host}:{Port} to {Email}.", host, smtp.Port, to);
    }
}
