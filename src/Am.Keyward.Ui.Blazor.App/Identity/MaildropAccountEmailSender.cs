using Am.Keyward.Core.Abstractions;
using Microsoft.Extensions.Options;

namespace Am.Keyward.Ui.Blazor.App.Identity;

public sealed class AccountEmailOptions
{
    public const string SectionName = "AccountEmail";

    /// <summary>Folder the reference maildrop sender writes account e-mails to. Empty -> ContentRoot/maildrop.</summary>
    public string? MaildropPath { get; set; }
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
    ILogger<MaildropAccountEmailSender> logger) : IAccountEmailSender
{
    public Task SendPasswordResetLinkAsync(string email, string resetLink, CancellationToken ct = default) =>
        DropAsync("password-reset", email, "AM KEYWARD password reset",
            $"Open this single-use link to set a new password:\r\n{resetLink}\r\n", ct);

    public Task SendEmailConfirmationLinkAsync(string email, string confirmLink, CancellationToken ct = default) =>
        DropAsync("confirm-email", email, "AM KEYWARD e-mail confirmation",
            $"Confirm your e-mail address to activate your account:\r\n{confirmLink}\r\n", ct);

    private async Task DropAsync(string kind, string email, string subject, string message, CancellationToken ct)
    {
        var dir = string.IsNullOrWhiteSpace(options.Value.MaildropPath)
            ? Path.Combine(environment.ContentRootPath, "maildrop")
            : options.Value.MaildropPath;
        Directory.CreateDirectory(dir);

        var stamp = clock.UtcNow.UtcDateTime.ToString("yyyyMMdd-HHmmssfff");
        var path = Path.Combine(dir, $"{kind}-{stamp}.txt");
        var body = $"To: {email}\r\nSubject: {subject}\r\n\r\n{message}";

        await File.WriteAllTextAsync(path, body, ct).ConfigureAwait(false);

        // Do NOT log the link/token — it is a single-use secret. Log only that a mail was dropped.
        logger.LogInformation(
            "Account e-mail ({Kind}) written to the maildrop folder for {Email}. Configure a real IAccountEmailSender (SMTP) for production delivery. Environment: {Environment}.",
            kind, email, environment.EnvironmentName);
    }
}
