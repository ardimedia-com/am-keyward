using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Am.Keyward.Ui.Blazor;

/// <summary>
/// Circuit-scoped UI state shared by the embedded Keyward pages: the application ("Project" in code) the
/// user last selected, so switching between the Applications / Software-Secrets / Client-Tokens pages keeps
/// operating on the same application. Purely a UI convenience — every service call still names the project
/// explicitly and is authorized server-side.
/// </summary>
public sealed class KeywardUiState
{
    public Guid? SelectedProjectId { get; set; }
}

/// <summary>
/// Host-configurable presentation options for the embedded Keyward UI. The host names the product as its
/// users should see it (browser tab, sidebar brand, texts that mention the product) — the default is the
/// neutral "AM KEYWARD".
/// </summary>
public sealed class KeywardUiOptions
{
    public string ProductName { get; set; } = "AM KEYWARD";

    /// <summary>
    /// The installation's public base URL (e.g. <c>https://keyward.example.com</c>), used to build absolute
    /// links in notification e-mails (which are sent from background jobs, outside any request). Optional —
    /// without it, notification mails simply carry no link button.
    /// </summary>
    public string? PublicBaseUrl { get; set; }

    /// <summary>
    /// Language (culture name, e.g. <c>"de"</c>) for e-mails sent from background jobs — the token-expiry
    /// notification — which have no request culture to follow. User-triggered account e-mails (password
    /// reset, confirmation) always use the request culture instead. Null/empty falls back to English.
    /// </summary>
    public string? NotificationLanguage { get; set; }
}

/// <summary>Registers the services the embedded Keyward UI pages need (see the README embedding guide).</summary>
public static class KeywardUiServiceCollectionExtensions
{
    public static IServiceCollection AddKeywardUi(this IServiceCollection services, Action<KeywardUiOptions>? configure = null)
    {
        var options = new KeywardUiOptions();
        configure?.Invoke(options);
        services.AddSingleton(options);
        services.AddScoped<KeywardUiState>();

        // Transient-notification port. The built-in toast host (KeywardToastState + DefaultKeywardNotifier)
        // is the STANDALONE default; a host with its own toasts (e.g. BlazorBlueprint's BbToast) overrides
        // IKeywardNotifier — registered with TryAdd so that host registration simply wins. The state is always
        // registered (the built-in host reads it; it just stays empty when a host override is used).
        services.AddScoped<KeywardToastState>();
        services.TryAddScoped<IKeywardNotifier, DefaultKeywardNotifier>();
        // Every Keyward page injects IStringLocalizer<SharedResource>; register localization so the host
        // does not have to (idempotent — a host's own AddLocalization call is unaffected). The resource
        // location is declared on THIS assembly (AssemblyInfo.cs), independent of the host's ResourcesPath.
        services.AddLocalization();
        return services;
    }
}
