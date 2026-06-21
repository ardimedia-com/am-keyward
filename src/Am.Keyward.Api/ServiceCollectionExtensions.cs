using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace Am.Keyward.Api;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers software-client API authentication: the <c>Keyward.SoftwareClient</c> Bearer scheme and
    /// an authorization policy requiring it. The host adds the authentication/authorization middleware and
    /// the per-token rate limiter (see the reference shell's Program.cs and
    /// <see cref="KeywardClientApi.RateLimiterPolicy"/>).
    /// </summary>
    public static IServiceCollection AddKeywardSoftwareClientApi(this IServiceCollection services)
    {
        services.AddAuthentication()
            .AddScheme<AuthenticationSchemeOptions, SoftwareClientAuthenticationHandler>(
                SoftwareClientAuthenticationHandler.SchemeName, _ => { });

        services.AddAuthorizationBuilder()
            .AddPolicy(SoftwareClientAuthenticationHandler.SchemeName, policy =>
            {
                policy.AddAuthenticationSchemes(SoftwareClientAuthenticationHandler.SchemeName);
                policy.RequireAuthenticatedUser();
            });

        return services;
    }
}
