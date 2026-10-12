using System.Security.Cryptography;
using System.Text;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Am.Keyward.Api;

/// <summary>Tuning for the software-client read API's per-token rate limiter.</summary>
public sealed class KeywardSoftwareClientApiOptions
{
    /// <summary>Requests allowed per token per <see cref="Window"/>. Default 60.</summary>
    public int PermitLimit { get; set; } = 60;

    /// <summary>Fixed-window length. Default 1 minute.</summary>
    public TimeSpan Window { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>Requests queued once the limit is hit. Default 0 (reject immediately).</summary>
    public int QueueLimit { get; set; }

    /// <summary>
    /// Failed token authentications allowed per client IP per <see cref="FailedAuthenticationWindow"/> before
    /// that IP is refused without a token lookup. Default 20.
    /// </summary>
    public int FailedAuthenticationLimit { get; set; } = 20;

    /// <summary>Fixed-window length for <see cref="FailedAuthenticationLimit"/>. Default 5 minutes.</summary>
    public TimeSpan FailedAuthenticationWindow { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>The configuration key a host conventionally binds <see cref="AllowedNetworks"/> from.</summary>
    public const string AllowedNetworksConfigurationKey = "Keyward:Client:AllowedNetworks";

    /// <summary>
    /// Comma-separated CIDR networks the software-client API accepts calls from (e.g. <c>10.1.0.0/23, 10.8.0.0/24</c>),
    /// conventionally bound from <see cref="AllowedNetworksConfigurationKey"/>. Checked before any token lookup; other
    /// callers get 403 with an empty body. Empty means any network — kept for backward compatibility, with a warning
    /// at startup. An unusable value (not CIDR, or containing a known reverse proxy) is logged as an error and the
    /// API refuses EVERY caller until it is corrected. Checked against <c>Connection.RemoteIpAddress</c>: behind a
    /// reverse proxy, resolve the real client with forwarded headers from that known proxy, and keep the proxy's
    /// network out of this list.
    /// </summary>
    public string? AllowedNetworks { get; set; }
}

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers everything the software-client read API needs: the <c>Keyward.SoftwareClient</c> Bearer
    /// scheme, an authorization policy requiring it, and the per-token fixed-window rate limiter under
    /// <see cref="KeywardClientApi.RateLimiterPolicy"/> — so a host can call <c>MapKeywardClientApi()</c>
    /// without hand-registering the limiter (which <c>MapKeywardClientApi</c> requires, previously a runtime
    /// footgun). The host still adds the authentication/authorization and rate-limiter <em>middleware</em>
    /// (<c>app.UseAuthentication()/UseAuthorization()</c>, <c>app.UseRateLimiter()</c>); Keyward's limiter
    /// policy composes with any the host registers itself.
    /// <para>
    /// Call <c>app.UseRateLimiter()</c> BEFORE <c>app.UseAuthentication()</c>: the token is validated inside the
    /// authorization middleware, so a limiter placed after it only ever sees requests that already cost a
    /// token lookup. Guessed tokens are additionally throttled per client IP (<see cref="FailedAuthenticationThrottle"/>).
    /// </para>
    /// <para>
    /// Set <see cref="KeywardSoftwareClientApiOptions.AllowedNetworks"/> (conventionally from
    /// <c>Keyward:Client:AllowedNetworks</c>) so only the networks of the deployed applications reach the token check;
    /// without it the API answers every network and a warning is logged at startup.
    /// </para>
    /// </summary>
    public static IServiceCollection AddKeywardSoftwareClientApi(
        this IServiceCollection services, Action<KeywardSoftwareClientApiOptions>? configure = null)
    {
        var options = new KeywardSoftwareClientApiOptions();
        configure?.Invoke(options);

        services.TryAddSingleton(new FailedAuthenticationThrottle(options));
        services.AddSingleton(sp => SoftwareClientNetworkPolicy.Parse(options.AllowedNetworks, KnownProxies(sp)));
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, KeywardNetworkPolicyStartupLog<SoftwareClientNetworkPolicy>>());

        services.AddAuthentication()
            .AddScheme<AuthenticationSchemeOptions, SoftwareClientAuthenticationHandler>(
                SoftwareClientAuthenticationHandler.SchemeName, _ => { });

        services.AddAuthorizationBuilder()
            .AddPolicy(SoftwareClientAuthenticationHandler.SchemeName, policy =>
            {
                policy.AddAuthenticationSchemes(SoftwareClientAuthenticationHandler.SchemeName);
                policy.RequireAuthenticatedUser();
            });

        services.AddRateLimiter(limiter =>
        {
            limiter.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            limiter.AddPolicy(KeywardClientApi.RateLimiterPolicy, httpContext =>
            {
                // Partition per token, but never hold the plaintext bearer token as the in-memory key: hash it,
                // so a limiter dump reveals no secrets and the key is fixed-width regardless of token length.
                var authHeader = httpContext.Request.Headers.Authorization.ToString();
                var partitionKey = string.IsNullOrEmpty(authHeader)
                    ? "ip:" + (httpContext.Connection.RemoteIpAddress?.ToString() ?? "anonymous")
                    : "tok:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(authHeader)));

                return RateLimitPartition.GetFixedWindowLimiter(partitionKey, _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = options.PermitLimit,
                    Window = options.Window,
                    QueueLimit = options.QueueLimit,
                });
            });
        });

        return services;
    }

    /// <summary>
    /// Registers the agent API: the <c>Keyward.Agent</c> Bearer scheme, an authorization policy requiring it and
    /// the per-token rate limiter <see cref="KeywardAgentApi.RateLimiterPolicy"/>. Like the software-client API,
    /// the host adds the middleware (<c>app.UseRateLimiter()</c> before <c>app.UseAuthentication()</c>) and maps
    /// the endpoints with <c>MapKeywardAgentApi()</c>. Failed authentications share the per-IP throttle with the
    /// software-client API.
    /// </summary>
    public static IServiceCollection AddKeywardAgentApi(
        this IServiceCollection services, Action<KeywardAgentApiOptions>? configure = null)
    {
        var options = new KeywardAgentApiOptions();
        configure?.Invoke(options);

        services.TryAddSingleton(new FailedAuthenticationThrottle(options.FailedAuthenticationLimit, options.FailedAuthenticationWindow));

        // Never throws: a malformed setting (a typo, a bare address without /32) must not take the
        // whole host down. It yields a policy that refuses every caller, and the startup log names the error.
        services.AddSingleton(sp => AgentNetworkPolicy.Parse(options.AllowedNetworks, KnownProxies(sp)));
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, KeywardNetworkPolicyStartupLog<AgentNetworkPolicy>>());

        services.AddAuthentication()
            .AddScheme<AuthenticationSchemeOptions, AgentAuthenticationHandler>(AgentAuthenticationHandler.SchemeName, _ => { });

        services.AddAuthorizationBuilder()
            .AddPolicy(AgentAuthenticationHandler.SchemeName, policy =>
            {
                policy.AddAuthenticationSchemes(AgentAuthenticationHandler.SchemeName);
                policy.RequireAuthenticatedUser();
            });

        services.AddRateLimiter(limiter =>
        {
            limiter.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            limiter.AddPolicy(KeywardAgentApi.RateLimiterPolicy, httpContext =>
            {
                var authHeader = httpContext.Request.Headers.Authorization.ToString();
                var partitionKey = string.IsNullOrEmpty(authHeader)
                    ? "ip:" + (httpContext.Connection.RemoteIpAddress?.ToString() ?? "anonymous")
                    : "tok:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(authHeader)));

                return RateLimitPartition.GetFixedWindowLimiter(partitionKey, _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = options.PermitLimit,
                    Window = options.Window,
                    QueueLimit = 0,
                });
            });
        });

        return services;
    }

    /// <summary>The host's trusted reverse proxies (<c>ForwardedHeadersOptions.KnownProxies</c>), which must stay outside any allowed network.</summary>
    private static IEnumerable<System.Net.IPAddress> KnownProxies(IServiceProvider services) =>
        services.GetService<IOptions<ForwardedHeadersOptions>>()?.Value.KnownProxies ?? [];
}

/// <summary>Tuning for the agent API.</summary>
public sealed class KeywardAgentApiOptions
{
    /// <summary>Requests allowed per token per <see cref="Window"/>. Default 120.</summary>
    public int PermitLimit { get; set; } = 120;

    /// <summary>Fixed-window length. Default 1 minute.</summary>
    public TimeSpan Window { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>
    /// Failed authentications per client IP per <see cref="FailedAuthenticationWindow"/>; used only when the
    /// software-client API is not registered (the throttle is shared). Default 20.
    /// </summary>
    public int FailedAuthenticationLimit { get; set; } = 20;

    /// <summary>Default 5 minutes.</summary>
    public TimeSpan FailedAuthenticationWindow { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>The configuration key a host conventionally binds <see cref="AllowedNetworks"/> from.</summary>
    public const string AllowedNetworksConfigurationKey = "Keyward:Agent:AllowedNetworks";

    /// <summary>
    /// Comma-separated CIDR networks the agent API accepts calls from (e.g. <c>10.1.0.0/23, 10.8.0.0/24</c>),
    /// conventionally bound from <see cref="AllowedNetworksConfigurationKey"/>; empty means any network. Checked before
    /// any token lookup; other callers get 403. An unusable value (not CIDR, or containing a known reverse proxy) is
    /// logged as an error at startup and the API refuses EVERY caller until it is corrected — it no longer stops the
    /// host. Checked against the address the host sees: behind a reverse proxy, keep the proxy address OUT of these
    /// networks (or resolve the real client address with forwarded headers from that known proxy), otherwise
    /// everything it forwards passes.
    /// </summary>
    public string? AllowedNetworks { get; set; }
}
