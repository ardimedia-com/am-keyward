using System.Net.Http.Headers;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Am.Keyward.Client;

/// <summary>
/// The two entry points of the client package: <see cref="AddKeywardSecrets(IConfigurationBuilder, Action{KeywardSecretsOptions})"/>
/// feeds an application's Keyward secrets into <c>IConfiguration</c> at startup, and
/// <see cref="AddKeywardSecretsClient"/> registers the typed <see cref="KeywardSecretsClient"/> for direct
/// runtime reads.
/// </summary>
public static class KeywardSecretsExtensions
{
    /// <summary>
    /// Adds the application's Keyward-hosted secrets as a configuration source. Registered after the file
    /// sources it overlays them, so <c>ConnectionStrings:Main</c> etc. resolve like any other configuration
    /// value. Fails the host at startup when Keyward is unreachable or no token is deployed, unless
    /// <see cref="KeywardSecretsOptions.Optional"/> is set.
    /// </summary>
    public static IConfigurationBuilder AddKeywardSecrets(this IConfigurationBuilder builder, Action<KeywardSecretsOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new KeywardSecretsOptions();
        configure(options);
        _ = options.ResolveApiBaseUri(); // fail fast on a missing/relative ServiceUri, at Add time
        return builder.Add(new KeywardSecretsConfigurationSource(options));
    }

    /// <summary>
    /// Convenience overload for the conventional setup: the token comes from the per-application
    /// environment variable (<c>Bvd.Li.Toolbox</c> → <c>KEYWARD_BVD_LI_TOOLBOX_TOKEN</c>) that the Keyward
    /// UI's deployment snippet sets on the host.
    /// </summary>
    public static IConfigurationBuilder AddKeywardSecrets(
        this IConfigurationBuilder builder, Uri serviceUri, string applicationName, bool optional = false) =>
        builder.AddKeywardSecrets(o =>
        {
            o.ServiceUri = serviceUri;
            o.ApplicationName = applicationName;
            o.Optional = optional;
        });

    /// <summary>
    /// Registers <see cref="KeywardSecretsClient"/> as a typed client via <see cref="IHttpClientFactory"/>
    /// for direct runtime reads (e.g. a secret fetched on demand rather than at startup). The token is
    /// resolved once per handler rotation from the same options/conventions as the configuration source.
    /// </summary>
    public static IServiceCollection AddKeywardSecretsClient(this IServiceCollection services, Action<KeywardSecretsOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.AddHttpClient<KeywardSecretsClient>(http =>
        {
            var options = new KeywardSecretsOptions();
            configure(options);

            var token = options.ResolveToken();
            if (string.IsNullOrWhiteSpace(token) && !options.Optional)
            {
                var variable = options.ResolveTokenVariableName();
                throw new InvalidOperationException(
                    variable is null
                        ? "No Keyward app token: set KeywardSecretsOptions.Token, TokenEnvironmentVariableName or ApplicationName."
                        : $"No Keyward app token: environment variable '{variable}' is not set.");
            }

            http.BaseAddress = options.ResolveApiBaseUri();
            http.Timeout = options.RequestTimeout;
            if (!string.IsNullOrWhiteSpace(token))
            {
                http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            }
        });
        return services;
    }
}
