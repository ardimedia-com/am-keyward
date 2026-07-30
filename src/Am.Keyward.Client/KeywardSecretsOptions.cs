using Am.Keyward.Contracts;

namespace Am.Keyward.Client;

/// <summary>
/// Settings for reading an application's secrets from a Keyward installation. The token is scoped
/// server-side to one (project, environment), so the client only needs to know where the installation
/// lives (<see cref="ServiceUri"/>) and how to obtain the token — by convention from the per-application
/// environment variable (<see cref="ApplicationName"/>), from a fixed variable
/// (<see cref="TokenEnvironmentVariableName"/>), or passed directly (<see cref="Token"/>).
/// </summary>
public sealed class KeywardSecretsOptions
{
    /// <summary>Root URL of the Keyward installation, e.g. <c>https://keyward.example.com</c>. Required.</summary>
    public Uri? ServiceUri { get; set; }

    /// <summary>The app token itself. When set, it wins over the environment-variable lookup.</summary>
    public string? Token { get; set; }

    /// <summary>
    /// The application's name as registered in Keyward (e.g. <c>Bvd.Li.Toolbox</c>). The token is then read
    /// from the conventional per-application environment variable
    /// (<see cref="KeywardTokenConventions.DeriveTokenVariableName"/> → <c>KEYWARD_BVD_LI_TOOLBOX_TOKEN</c>)
    /// — the same variable the Keyward UI's deployment PowerShell snippet sets on the host.
    /// </summary>
    public string? ApplicationName { get; set; }

    /// <summary>
    /// Fixed name of the environment variable holding the token. Wins over the name derived from
    /// <see cref="ApplicationName"/>; for installations whose applications all read one fixed variable.
    /// </summary>
    public string? TokenEnvironmentVariableName { get; set; }

    /// <summary>
    /// Path the software-client API is mapped at on the server (the <c>prefix</c> passed to
    /// <c>MapKeywardClientApi</c>). Change it only when the host maps the API somewhere non-default.
    /// </summary>
    public string ApiBasePath { get; set; } = KeywardApiDefaults.BasePath;

    /// <summary>
    /// When <c>true</c>, a missing token or unreachable server yields an empty configuration source instead
    /// of failing the host. Default <c>false</c>: an app whose secrets live in Keyward should fail loudly at
    /// startup rather than silently run without them.
    /// </summary>
    public bool Optional { get; set; }

    /// <summary>
    /// When set, the provider re-reads the secrets on this interval and raises a configuration reload when
    /// they changed (options snapshots/monitors pick it up). Null (default) loads once at startup.
    /// </summary>
    public TimeSpan? ReloadInterval { get; set; }

    /// <summary>Timeout for a single HTTP request.</summary>
    public TimeSpan RequestTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Additional attempts after a failed initial load, so a service starting right after a host reboot does
    /// not lose the race against the Keyward server coming up. Retries apply to the startup load only;
    /// periodic reloads keep the last known good values on failure instead.
    /// </summary>
    public int LoadRetryCount { get; set; } = 2;

    /// <summary>Delay between startup-load attempts (doubled per attempt).</summary>
    public TimeSpan LoadRetryDelay { get; set; } = TimeSpan.FromSeconds(2);

    /// <summary>
    /// Advanced: the HTTP transport to use instead of the default (proxies, custom TLS handling, tests).
    /// The provider disposes it together with its <see cref="HttpClient"/>.
    /// </summary>
    public HttpMessageHandler? HttpMessageHandler { get; set; }

    /// <summary>The environment variable a token lookup would read, or null when none is determinable.</summary>
    public string? ResolveTokenVariableName() =>
        !string.IsNullOrWhiteSpace(TokenEnvironmentVariableName) ? TokenEnvironmentVariableName
        : !string.IsNullOrWhiteSpace(ApplicationName) ? KeywardTokenConventions.DeriveTokenVariableName(ApplicationName!)
        : null;

    /// <summary>The effective token: <see cref="Token"/> if set, else the environment variable's value.</summary>
    internal string? ResolveToken()
    {
        if (!string.IsNullOrWhiteSpace(Token))
        {
            return Token;
        }

        var variable = ResolveTokenVariableName();
        return variable is null ? null : Environment.GetEnvironmentVariable(variable);
    }

    /// <summary>Base URI all requests resolve against: <see cref="ServiceUri"/> + <see cref="ApiBasePath"/>, slash-terminated.</summary>
    internal Uri ResolveApiBaseUri()
    {
        if (ServiceUri is null || !ServiceUri.IsAbsoluteUri)
        {
            throw new InvalidOperationException("KeywardSecretsOptions.ServiceUri must be an absolute URL (e.g. https://keyward.example.com).");
        }

        // Slash-terminate the root so a ServiceUri with a sub-path (https://host/app) keeps that path when
        // the relative API base path is resolved against it.
        var root = ServiceUri.AbsoluteUri.EndsWith('/') ? ServiceUri : new Uri(ServiceUri.AbsoluteUri + "/");
        return new Uri(root, ApiBasePath.Trim('/') + "/");
    }
}
