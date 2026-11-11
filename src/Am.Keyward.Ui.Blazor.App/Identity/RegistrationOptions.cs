using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Am.Keyward.Ui.Blazor.App;

/// <summary>How accounts come into existence on this installation.</summary>
public enum RegistrationMode
{
    /// <summary>
    /// Default. Only a system admin creates accounts, by invitation (a single-use, short-lived set-password link).
    /// The register page works only on an EMPTY installation — the first-run path that creates the system admin.
    /// </summary>
    InviteOnly,

    /// <summary>
    /// Anyone who can reach the site may register; every confirmed account becomes a member of the tenant.
    /// Demo use only.
    /// </summary>
    Open,
}

/// <summary>Self-registration and invitation settings (<c>Keyward:Registration</c>).</summary>
public sealed class RegistrationOptions
{
    public const string SectionName = "Keyward:Registration";

    /// <summary>Configuration key of <see cref="Mode"/>.</summary>
    public const string ModeKey = SectionName + ":Mode";

    /// <summary><see cref="RegistrationMode.InviteOnly"/> unless configured otherwise.</summary>
    public RegistrationMode Mode { get; set; } = RegistrationMode.InviteOnly;

    /// <summary>How long an invitation link stays valid. Default 48 hours.</summary>
    public int InvitationLifetimeHours { get; set; } = 48;
}

/// <summary>Answers whether the register page may create an account right now.</summary>
public sealed class RegistrationGate(UserManager<IdentityUser> users, IOptions<RegistrationOptions> options)
{
    public RegistrationMode Mode => options.Value.Mode;

    /// <summary>Whether the installation has no account yet (the first account becomes the system admin).</summary>
    public async Task<bool> IsEmptyInstallationAsync(CancellationToken ct = default) =>
        !await users.Users.AnyAsync(ct);

    /// <summary>Open mode, or the first-run path of an empty installation.</summary>
    public async Task<bool> IsRegistrationAllowedAsync(CancellationToken ct = default) =>
        Mode == RegistrationMode.Open || await IsEmptyInstallationAsync(ct);
}
