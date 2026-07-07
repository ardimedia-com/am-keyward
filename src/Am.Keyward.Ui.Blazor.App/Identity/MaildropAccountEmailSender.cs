using Am.Keyward.Core.Abstractions;
using Am.Keyward.Ui.Blazor;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Options;

namespace Am.Keyward.Ui.Blazor.App.Identity;

public sealed class AccountEmailOptions
{
    public const string SectionName = "AccountEmail";

    /// <summary>Folder the reference maildrop sender writes account e-mails to. Empty -> ContentRoot/maildrop.</summary>
    public string? MaildropPath { get; set; }

    /// <summary>SMTP relay settings. When <see cref="SmtpOptions.Host"/> is set, account e-mails are actually
    /// sent over SMTP; otherwise they are dropped to the maildrop folder.</summary>
    public SmtpOptions Smtp { get; set; } = new();
}

/// <summary>SMTP relay settings for account e-mails (password reset, e-mail confirmation).</summary>
public sealed class SmtpOptions
{
    /// <summary>Relay host, e.g. <c>smtptest.ardimedia.com</c>. Empty selects the maildrop sender instead.</summary>
    public string? Host { get; set; }

    /// <summary>Relay port. Default 25 (typical internal relay).</summary>
    public int Port { get; set; } = 25;

    /// <summary>From address for account e-mails (required when <see cref="Host"/> is set).</summary>
    public string From { get; set; } = "";

    /// <summary>Optional relay credentials — internal relays usually need none.</summary>
    public string? User { get; set; }

    public string? Password { get; set; }
}

/// <summary>
/// Reference <see cref="IAccountEmailSender"/> that writes each account e-mail to a local <c>maildrop</c>
/// folder instead of sending it over SMTP, so the flow works in a self-hosted shell with no mail server: the
/// operator (who has filesystem access) reads the drop file. A real deployment replaces this with an SMTP
/// sender. The link is written only to the drop file (the delivery channel), never to the log.
/// </summary>
public sealed class MaildropAccountEmailSender(
    IOptions<AccountEmailOptions> options,
    IHostEnvironment environment,
    IClock clock,
    KeywardUiOptions uiOptions,
    IStringLocalizer<SharedResource> loc,
    ILogger<MaildropAccountEmailSender> logger) : IAccountEmailSender
{
    public Task SendPasswordResetLinkAsync(string email, string resetLink, CancellationToken ct = default)
    {
        var (subject, content) = AccountEmailMessages.PasswordReset(loc, uiOptions.ProductName, resetLink);
        return DropAsync("password-reset", email, subject, content, ct);
    }

    public Task SendEmailConfirmationLinkAsync(string email, string confirmLink, CancellationToken ct = default)
    {
        var (subject, content) = AccountEmailMessages.EmailConfirmation(loc, uiOptions.ProductName, confirmLink);
        return DropAsync("confirm-email", email, subject, content, ct);
    }

    public Task SendAsync(string email, string subject, BrandedEmailContent content, CancellationToken ct = default) =>
        DropAsync("notification", email, subject, content, ct);

    private async Task DropAsync(string kind, string email, string subject, BrandedEmailContent content, CancellationToken ct)
    {
        var dir = string.IsNullOrWhiteSpace(options.Value.MaildropPath)
            ? Path.Combine(environment.ContentRootPath, "maildrop")
            : options.Value.MaildropPath;
        Directory.CreateDirectory(dir);

        var stamp = clock.UtcNow.UtcDateTime.ToString("yyyyMMdd-HHmmssfff");

        // The branded HTML card (openable in a browser to preview exactly what a recipient sees) plus the
        // plain-text alternative, from the same source content (BrandedEmail).
        var htmlPath = Path.Combine(dir, $"{kind}-{stamp}.html");
        await File.WriteAllTextAsync(htmlPath, BrandedEmail.RenderHtml(content), ct).ConfigureAwait(false);

        var textPath = Path.Combine(dir, $"{kind}-{stamp}.txt");
        var text = $"To: {email}\r\nSubject: {subject}\r\n\r\n{BrandedEmail.RenderText(content)}";
        await File.WriteAllTextAsync(textPath, text, ct).ConfigureAwait(false);

        // Do NOT log the link/token — it is a single-use secret. Log only that a mail was dropped.
        logger.LogInformation(
            "Account e-mail ({Kind}) written to the maildrop folder for {Email}. Configure a real IAccountEmailSender (SMTP) for production delivery. Environment: {Environment}.",
            kind, email, environment.EnvironmentName);
    }
}
