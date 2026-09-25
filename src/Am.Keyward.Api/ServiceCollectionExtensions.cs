using System.Security.Cryptography;
using System.Text;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

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
    /// </summary>
    public static IServiceCollection AddKeywardSoftwareClientApi(
        this IServiceCollection services, Action<KeywardSoftwareClientApiOptions>? configure = null)
    {
        var options = new KeywardSoftwareClientApiOptions();
        configure?.Invoke(options);

        services.TryAddSingleton(new FailedAuthenticationThrottle(options));

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
}
