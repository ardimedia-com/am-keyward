using System.Security.Cryptography;
using System.Text;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.DependencyInjection;

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
    /// </summary>
    public static IServiceCollection AddKeywardSoftwareClientApi(
        this IServiceCollection services, Action<KeywardSoftwareClientApiOptions>? configure = null)
    {
        var options = new KeywardSoftwareClientApiOptions();
        configure?.Invoke(options);

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
}
