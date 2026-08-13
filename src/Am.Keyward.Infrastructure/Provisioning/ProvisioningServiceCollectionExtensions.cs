using Am.Keyward.Core.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Am.Keyward.Infrastructure.Provisioning;

/// <summary>
/// Registration for the provisioning diagnostics — deliberately SEPARATE from <c>AddKeyward</c>.
/// <para>
/// A host registers this <b>unconditionally</b>, including in an environment where it does not call
/// <c>AddKeyward</c> at all: explaining a dormant or half-configured install is exactly what these
/// diagnostics are for, so they must exist precisely when the rest of Keyward does not. Nothing here
/// resolves a Keyward service; the checks read configuration and talk to SQL directly.
/// </para>
/// </summary>
public static class ProvisioningServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="KeywardProvisioningStatusService"/> (what a status page renders) and, when
    /// <paramref name="addStartupCheck"/> is set, the one-shot startup diagnostic that logs the remaining
    /// gaps shortly after boot.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="environment">The host environment (see <see cref="IKeywardHostEnvironment"/>).</param>
    /// <param name="configure">The host's own facts: tenant, key directory, connection-string key, policy.</param>
    /// <param name="addStartupCheck">
    /// Whether to log the gaps once at startup. Pass <c>false</c> where Keyward is switched off and that is
    /// expected, so a dormant environment stays quiet.
    /// </param>
    public static IServiceCollection AddKeywardProvisioningStatus(
        this IServiceCollection services,
        IKeywardHostEnvironment environment,
        Action<KeywardProvisioningOptions> configure,
        bool addStartupCheck = true)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(environment);
        ArgumentNullException.ThrowIfNull(configure);

        services.AddSingleton(environment);
        services.Configure(configure);
        services.AddScoped<KeywardProvisioningStatusService>();
        services.AddScoped<IKeywardProvisioningStatus>(sp => sp.GetRequiredService<KeywardProvisioningStatusService>());

        if (addStartupCheck)
        {
            services.AddHostedService<KeywardProvisioningStartupCheck>();
        }

        return services;
    }

    /// <summary>
    /// Registers <see cref="Software.KeywardMachineSecrets"/> — the in-process reader for the HOST'S OWN
    /// machine credentials (Keyward-first with configuration fallback). Requires <c>AddKeyward</c> (for the
    /// secret/project services) and an <see cref="IKeywardHostEnvironment"/>, which
    /// <see cref="AddKeywardProvisioningStatus"/> already registers.
    /// </summary>
    /// <param name="applicationName">
    /// The Keyward application holding this host's credentials — by convention its entry-assembly name, and
    /// the same name the startup seed creates the application under.
    /// </param>
    public static IServiceCollection AddKeywardMachineSecrets(this IServiceCollection services, string applicationName)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrWhiteSpace(applicationName);

        services.Configure<Software.KeywardMachineSecretsOptions>(o => o.ApplicationName = applicationName);
        services.AddScoped<Software.KeywardMachineSecrets>();
        return services;
    }
}

/// <summary>
/// The default <see cref="IKeywardHostEnvironment"/>: reads the two values off any
/// <see cref="IHostEnvironment"/>, so an ASP.NET Core host passes its own environment straight through.
/// </summary>
public sealed class KeywardHostEnvironment(IHostEnvironment environment) : IKeywardHostEnvironment
{
    public string EnvironmentName => environment.EnvironmentName;

    public bool IsDevelopment => environment.IsDevelopment();
}
