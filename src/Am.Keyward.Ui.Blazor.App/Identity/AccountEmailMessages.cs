namespace Am.Keyward.Ui.Blazor.App.Identity;

/// <summary>
/// The subject + branded content of each account e-mail, defined once so every transport
/// (<see cref="SmtpAccountEmailSender"/>, <see cref="MaildropAccountEmailSender"/>) renders exactly the same
/// message. The product name comes from the host configuration (<c>KeywardUiOptions.ProductName</c>).
/// Content is English (the product lingua franca) — the recipient's culture is not known at send time
/// on the anonymous forgot-password / resend-confirmation paths.
/// </summary>
internal static class AccountEmailMessages
{
    public static (string Subject, BrandedEmailContent Content) PasswordReset(string resetLink, string productName) =>
        ($"{productName} password reset", new BrandedEmailContent
        {
            Brand = productName,
            Title = "Reset your password",
            Paragraphs =
            [
                $"We received a request to set a new password for your {productName} account.",
                "Click the button below to choose a new password. This link is single-use and expires shortly.",
            ],
            ButtonText = "Set a new password",
            ActionUrl = resetLink,
            FooterNote = "If you did not request this, you can safely ignore this e-mail — your password stays unchanged.",
        });

    public static (string Subject, BrandedEmailContent Content) EmailConfirmation(string confirmLink, string productName) =>
        ($"{productName} e-mail confirmation", new BrandedEmailContent
        {
            Brand = productName,
            Title = "Confirm your e-mail address",
            Paragraphs =
            [
                $"Welcome to {productName}. Please confirm your e-mail address to activate your account.",
                "Click the button below to complete your registration.",
            ],
            ButtonText = "Confirm e-mail address",
            ActionUrl = confirmLink,
            FooterNote = $"If you did not create a {productName} account, you can safely ignore this e-mail.",
        });
}
