namespace Am.Keyward.Ui.Blazor.App.Identity;

/// <summary>
/// Delivers account e-mails (currently the password-reset link). Delivery is host-specific infrastructure,
/// so the reference shell ships a file <c>maildrop</c> implementation and a real deployment replaces this
/// with an SMTP sender (e.g. MailKit through the operator's relay). Implementations MUST NOT log the link or
/// token — the link is a single-use secret; the maildrop file is the delivery channel (like the inbox).
/// </summary>
public interface IAccountEmailSender
{
    Task SendPasswordResetLinkAsync(string email, string resetLink, CancellationToken ct = default);

    Task SendEmailConfirmationLinkAsync(string email, string confirmLink, CancellationToken ct = default);
}
