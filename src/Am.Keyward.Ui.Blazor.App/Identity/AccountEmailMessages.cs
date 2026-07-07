using Am.Keyward.Ui.Blazor;
using Microsoft.Extensions.Localization;

namespace Am.Keyward.Ui.Blazor.App.Identity;

/// <summary>
/// The subject + branded content of each account e-mail, defined once so every transport
/// (<see cref="SmtpAccountEmailSender"/>, <see cref="MaildropAccountEmailSender"/>) renders exactly the same
/// message. Strings are localized via <see cref="IStringLocalizer{SharedResource}"/> in the caller's current
/// UI culture — for these user-triggered mails that is the request culture — and the product name comes from
/// the host configuration (<c>KeywardUiOptions.ProductName</c>).
/// </summary>
internal static class AccountEmailMessages
{
    public static (string Subject, BrandedEmailContent Content) PasswordReset(
        IStringLocalizer<SharedResource> loc, string productName, string resetLink) =>
        (loc["Email.Reset.Subject", productName].Value, new BrandedEmailContent
        {
            Brand = productName,
            Title = loc["Email.Reset.Title"].Value,
            Paragraphs =
            [
                loc["Email.Reset.Body1", productName].Value,
                loc["Email.Reset.Body2"].Value,
            ],
            ButtonText = loc["Email.Reset.Button"].Value,
            ActionUrl = resetLink,
            FooterNote = loc["Email.Reset.Footer"].Value,
        });

    public static (string Subject, BrandedEmailContent Content) EmailConfirmation(
        IStringLocalizer<SharedResource> loc, string productName, string confirmLink) =>
        (loc["Email.Confirm.Subject", productName].Value, new BrandedEmailContent
        {
            Brand = productName,
            Title = loc["Email.Confirm.Title"].Value,
            Paragraphs =
            [
                loc["Email.Confirm.Body1", productName].Value,
                loc["Email.Confirm.Body2"].Value,
            ],
            ButtonText = loc["Email.Confirm.Button"].Value,
            ActionUrl = confirmLink,
            FooterNote = loc["Email.Confirm.Footer", productName].Value,
        });
}
