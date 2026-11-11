using System.Net;
using Microsoft.AspNetCore.HttpOverrides;

namespace Am.Keyward.Ui.Blazor.App.Hosting;

/// <summary>
/// The configuration the reference shell refuses to start without. Every check is a misconfiguration that would
/// otherwise fail silently and dangerously: an unset environment resolves to a Production posture on a Development
/// connection, account e-mails would carry links to whatever host the request named, a typo in a mode would fall
/// back to a default nobody chose. Pure (configuration in, messages out), so the rules are testable without
/// booting the host.
/// </summary>
public static class ShellStartupValidation
{
    /// <summary>Absolute public address of the installation; account and notification links are built from it.</summary>
    public const string PublicBaseUrlKey = "Keyward:PublicBaseUrl";

    /// <summary>The SQL Server connection string of the Keyward database (and the shell's Identity tables).</summary>
    public const string ConnectionStringName = "Keyward";

    /// <summary>
    /// Returns every reason the shell must not start; empty when it may.
    /// </summary>
    /// <param name="configuration">The host configuration.</param>
    /// <param name="explicitEnvironment">
    /// The environment as the operator set it (<c>ASPNETCORE_ENVIRONMENT</c>, <c>DOTNET_ENVIRONMENT</c> or
    /// <c>--environment</c>); <c>null</c> when nothing was set — NOT the framework's Production fallback.
    /// </param>
    /// <param name="isDevelopment">Whether the resolved environment is Development.</param>
    public static IReadOnlyList<string> Validate(IConfiguration configuration, string? explicitEnvironment, bool isDevelopment)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        if (string.IsNullOrWhiteSpace(explicitEnvironment))
        {
            // Nothing else is meaningful without an environment: which overlay, which database, which posture.
            return
            [
                "No environment set. Set ASPNETCORE_ENVIRONMENT or DOTNET_ENVIRONMENT to 'Development', 'Test' or "
                + "'Production' (machine scope on servers). Refusing to start to avoid connecting to the wrong database "
                + "or mailing real recipients.",
            ];
        }

        var errors = new List<string>();

        if (!isDevelopment)
        {
            if (string.IsNullOrWhiteSpace(configuration.GetConnectionString(ConnectionStringName)))
            {
                errors.Add($"ConnectionStrings:{ConnectionStringName} is not set. Outside Development the shell has no "
                    + "fallback connection string; configure the database explicitly.");
            }

            var publicBaseUrl = configuration[PublicBaseUrlKey];
            if (!Uri.TryCreate(publicBaseUrl, UriKind.Absolute, out var baseUri) || baseUri.Scheme != Uri.UriSchemeHttps)
            {
                errors.Add($"{PublicBaseUrlKey} must be the absolute https address users reach this installation at "
                    + "(e.g. https://keyward.example.com). Outside Development account e-mails build their links from it, "
                    + "never from the request's Host header.");
            }
        }

        var mode = configuration[RegistrationOptions.ModeKey];
        if (!string.IsNullOrWhiteSpace(mode) && !Enum.TryParse<RegistrationMode>(mode, ignoreCase: true, out _))
        {
            errors.Add($"{RegistrationOptions.ModeKey} '{mode}' is not valid. Use 'InviteOnly' (default) or 'Open'.");
        }

        errors.AddRange(ShellForwardedHeaders.Validate(configuration));
        return errors;
    }

    /// <summary>
    /// The environment as the operator set it, or <c>null</c>. Reads the host configuration key that
    /// <c>ASPNETCORE_ENVIRONMENT</c>, <c>DOTNET_ENVIRONMENT</c> and <c>--environment</c> all land on (so the
    /// framework-resolved value, including test hosts), then the raw variables as a fallback.
    /// </summary>
    public static string? ExplicitEnvironment(IConfiguration configuration) =>
        NullIfBlank(configuration[HostDefaults.EnvironmentKey])
        ?? NullIfBlank(Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT"))
        ?? NullIfBlank(Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT"));

    private static string? NullIfBlank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;
}

/// <summary>
/// Reverse-proxy support: resolves the real client address from <c>X-Forwarded-For</c> / <c>X-Forwarded-Proto</c>,
/// trusted ONLY from the configured proxies. Without it every caller behind a proxy has the proxy's address, which
/// breaks the per-IP throttling and the network allow-lists of the client and agent APIs. Off when nothing is
/// configured.
/// </summary>
public static class ShellForwardedHeaders
{
    /// <summary>Comma- or semicolon-separated IP addresses of the trusted reverse proxies.</summary>
    public const string KnownProxiesKey = "Keyward:ForwardedHeaders:KnownProxies";

    /// <summary>Comma- or semicolon-separated CIDR networks of trusted reverse proxies (e.g. a proxy pool).</summary>
    public const string KnownNetworksKey = "Keyward:ForwardedHeaders:KnownNetworks";

    /// <summary>Whether forwarded headers are configured at all.</summary>
    public static bool IsEnabled(IConfiguration configuration) =>
        Split(configuration[KnownProxiesKey]).Length > 0 || Split(configuration[KnownNetworksKey]).Length > 0;

    /// <summary>Messages for every entry that is not a valid address / network.</summary>
    public static IEnumerable<string> Validate(IConfiguration configuration)
    {
        foreach (var entry in Split(configuration[KnownProxiesKey]))
        {
            if (!IPAddress.TryParse(entry, out _))
            {
                yield return $"{KnownProxiesKey}: '{entry}' is not an IP address.";
            }
        }

        foreach (var entry in Split(configuration[KnownNetworksKey]))
        {
            if (!System.Net.IPNetwork.TryParse(entry, out _))
            {
                yield return $"{KnownNetworksKey}: '{entry}' is not a CIDR network (e.g. 10.0.0.0/24).";
            }
        }
    }

    /// <summary>Applies the configured proxies; the framework's loopback defaults are replaced, not extended.</summary>
    public static void Configure(ForwardedHeadersOptions options, IConfiguration configuration)
    {
        options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
        options.KnownProxies.Clear();
        options.KnownIPNetworks.Clear();
        foreach (var entry in Split(configuration[KnownProxiesKey]))
        {
            options.KnownProxies.Add(IPAddress.Parse(entry));
        }

        foreach (var entry in Split(configuration[KnownNetworksKey]))
        {
            options.KnownIPNetworks.Add(System.Net.IPNetwork.Parse(entry));
        }
    }

    private static string[] Split(string? value) =>
        (value ?? "").Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}

/// <summary>
/// Whether a return URL may be followed after sign-in (or after a language switch): only paths on this site — a
/// single leading <c>/</c>, not <c>//host</c> or <c>/\host</c> (both are read as another host by browsers), and no
/// control characters. Mirrors ASP.NET Core's <c>IUrlHelper.IsLocalUrl</c> without the <c>~/</c> form.
/// </summary>
public static class LocalUrl
{
    public static bool IsLocal(string? url)
    {
        if (string.IsNullOrEmpty(url) || url[0] != '/')
        {
            return false;
        }

        if (url.Length > 1 && (url[1] == '/' || url[1] == '\\'))
        {
            return false;
        }

        return !url.Any(char.IsControl);
    }

    /// <summary><paramref name="url"/> when it is local, otherwise <c>/</c>.</summary>
    public static string OrRoot(string? url) => IsLocal(url) ? url! : "/";
}
