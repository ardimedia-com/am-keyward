using System.ComponentModel.DataAnnotations;
using System.Text;
using Am.Keyward.Ui.Blazor;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Options;

namespace Am.Keyward.Ui.Blazor.App.Identity;

/// <summary>Options of the invitation token provider: its own (short) lifespan, separate from password reset.</summary>
public sealed class InvitationTokenProviderOptions : DataProtectionTokenProviderOptions
{
    public InvitationTokenProviderOptions()
    {
        Name = InvitationTokenProvider.ProviderName;
        TokenLifespan = TimeSpan.FromHours(48);
    }
}

/// <summary>
/// Data-protection token provider for invitation links. The token embeds the user's security stamp, and
/// accepting an invitation rotates it — so a link works once.
/// </summary>
public sealed class InvitationTokenProvider(
    IDataProtectionProvider dataProtectionProvider,
    IOptions<InvitationTokenProviderOptions> options,
    ILogger<DataProtectorTokenProvider<IdentityUser>> logger)
    : DataProtectorTokenProvider<IdentityUser>(dataProtectionProvider, options, logger)
{
    public const string ProviderName = "KeywardInvitation";
}

/// <summary>What happened to an invitation request.</summary>
public enum InvitationOutcome
{
    Sent,
    InvalidEmail,
    AlreadyActive,
    MailFailed,
}

/// <summary>
/// Invite-only onboarding (<see cref="RegistrationMode.InviteOnly"/>): a system admin invites an e-mail address,
/// which creates the account unconfirmed, without password and locked (pending), and mails a single-use,
/// short-lived set-password link built from the public base URL. Accepting sets the password, confirms the
/// address, lifts the pending lock and rotates the security stamp (the link is spent).
/// </summary>
public sealed class InvitationService(
    UserManager<IdentityUser> users,
    IAccountEmailSender sender,
    AccountLinkBuilder links,
    KeywardUiOptions uiOptions,
    IStringLocalizer<ShellResource> loc,
    IOptions<RegistrationOptions> registration,
    ILogger<InvitationService> logger)
{
    /// <summary>Token purpose; distinct from every other Identity token.</summary>
    public const string Purpose = "KeywardInvitation";

    /// <summary>The page the invitation link opens.</summary>
    public const string AcceptPath = "account/accept-invitation";

    /// <summary>
    /// A pending invitation: never confirmed, no password yet, held by the pending lock. An administratively
    /// disabled account always has a password or a confirmed address, so the two never look alike.
    /// </summary>
    public static bool IsPending(IdentityUser user) =>
        !user.EmailConfirmed && user.PasswordHash is null && user.LockoutEnd is { } end && end >= DateTimeOffset.MaxValue.AddDays(-1);

    /// <summary>Creates (or re-issues) the invitation for <paramref name="email"/> and mails the link.</summary>
    public async Task<InvitationOutcome> InviteAsync(string? email, CancellationToken ct = default)
    {
        email = email?.Trim();
        if (string.IsNullOrEmpty(email) || !new EmailAddressAttribute().IsValid(email))
        {
            return InvitationOutcome.InvalidEmail;
        }

        var user = await users.FindByEmailAsync(email);
        if (user is null)
        {
            user = new IdentityUser { UserName = email, Email = email, EmailConfirmed = false, LockoutEnabled = true };
            var created = await users.CreateAsync(user);
            if (!created.Succeeded)
            {
                logger.LogWarning("Creating the invited account failed: {Errors}",
                    string.Join(", ", created.Errors.Select(e => e.Code)));
                return InvitationOutcome.InvalidEmail;
            }

            // The pending lock: sign-in and password reset cannot open the account; only the invitation can.
            await users.SetLockoutEndDateAsync(user, DateTimeOffset.MaxValue);
        }
        else if (!IsPending(user))
        {
            return InvitationOutcome.AlreadyActive;
        }
        else
        {
            // Re-issuing: the previous link stops working.
            await users.UpdateSecurityStampAsync(user);
        }

        var token = await users.GenerateUserTokenAsync(user, InvitationTokenProvider.ProviderName, Purpose);
        var link = links.Build(AcceptPath, new Dictionary<string, string?>
        {
            ["userId"] = user.Id,
            ["token"] = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token)),
        });

        var hours = registration.Value.InvitationLifetimeHours;
        var content = new BrandedEmailContent
        {
            Brand = uiOptions.ProductName,
            Title = loc["Email.Invite.Title"].Value,
            Paragraphs =
            [
                loc["Email.Invite.Body1", uiOptions.ProductName].Value,
                loc["Email.Invite.Body2", hours].Value,
            ],
            ButtonText = loc["Email.Invite.Button"].Value,
            ActionUrl = link,
            FooterNote = loc["Email.Invite.Footer"].Value,
        };

        try
        {
            await sender.SendAsync(email, loc["Email.Invite.Subject", uiOptions.ProductName].Value, content, ct);
            return InvitationOutcome.Sent;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to send the invitation e-mail to {Email}.", email);
            return InvitationOutcome.MailFailed;
        }
    }

    /// <summary>The pending user the link belongs to when the link is still valid; otherwise <c>null</c>.</summary>
    public async Task<IdentityUser?> FindValidAsync(string? userId, string? encodedToken)
    {
        if (string.IsNullOrEmpty(userId) || DecodeToken(encodedToken) is not { } token)
        {
            return null;
        }

        var user = await users.FindByIdAsync(userId);
        return user is not null && IsPending(user)
            && await users.VerifyUserTokenAsync(user, InvitationTokenProvider.ProviderName, Purpose, token)
            ? user
            : null;
    }

    /// <summary>
    /// Accepts the invitation: sets <paramref name="password"/>, confirms the address, lifts the pending lock and
    /// spends the link. <c>LinkValid</c> is <c>false</c> when the link is invalid, used or expired; otherwise
    /// <c>Result</c> carries the password-policy outcome.
    /// </summary>
    public async Task<(bool LinkValid, IdentityResult? Result)> AcceptAsync(string? userId, string? encodedToken, string password)
    {
        var user = await FindValidAsync(userId, encodedToken);
        if (user is null)
        {
            return (false, null);
        }

        var added = await users.AddPasswordAsync(user, password);
        if (!added.Succeeded)
        {
            return (true, added);
        }

        user.EmailConfirmed = true;
        await users.UpdateAsync(user);
        await users.SetLockoutEndDateAsync(user, null);
        await users.ResetAccessFailedCountAsync(user);
        await users.UpdateSecurityStampAsync(user);   // single use: the link (and any re-issued one) is spent
        return (true, IdentityResult.Success);
    }

    private static string? DecodeToken(string? encoded)
    {
        if (string.IsNullOrEmpty(encoded))
        {
            return null;
        }

        try
        {
            return Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(encoded));
        }
        catch (FormatException)
        {
            return null;
        }
    }
}
