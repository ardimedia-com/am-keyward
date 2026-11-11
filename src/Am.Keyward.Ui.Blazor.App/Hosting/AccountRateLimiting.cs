using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Localization;

namespace Am.Keyward.Ui.Blazor.App.Hosting;

/// <summary>Per-IP limit on the account form posts (<c>Keyward:AccountRateLimit</c>).</summary>
public sealed class AccountRateLimitOptions
{
    public const string SectionName = "Keyward:AccountRateLimit";

    /// <summary>Form posts per client address and window. Default 20.</summary>
    public int PermitLimit { get; set; } = 20;

    /// <summary>Window length in seconds. Default 300 (5 minutes).</summary>
    public int WindowSeconds { get; set; } = 300;
}

/// <summary>
/// Throttles the anonymous account form posts (sign-in, registration, forgot/reset password, invitation) per client
/// address, ahead of any credential check. The per-account lockout stops guessing one password; this stops spraying
/// many accounts from one address — and keeps the targeted-lockout DoS window small. Runs as the global limiter
/// (the library's token-API limiters are endpoint policies and stay untouched); behind a reverse proxy it needs
/// <see cref="ShellForwardedHeaders"/>, or every caller shares the proxy's address.
/// </summary>
public static class AccountRateLimiting
{
    private static readonly string[] AccountFormPaths =
    [
        "/account/login",
        "/account/register",
        "/account/forgot-password",
        "/account/reset-password",
        "/account/accept-invitation",
    ];

    /// <summary>Whether <paramref name="context"/> is a throttled account form post.</summary>
    public static bool IsAccountFormPost(HttpContext context) =>
        HttpMethods.IsPost(context.Request.Method)
        && AccountFormPaths.Any(p => context.Request.Path.Equals(p, StringComparison.OrdinalIgnoreCase));

    public static IServiceCollection AddKeywardAccountRateLimiting(this IServiceCollection services, IConfiguration configuration)
    {
        var options = configuration.GetSection(AccountRateLimitOptions.SectionName).Get<AccountRateLimitOptions>()
            ?? new AccountRateLimitOptions();
        var permitLimit = Math.Max(1, options.PermitLimit);
        var window = TimeSpan.FromSeconds(Math.Max(1, options.WindowSeconds));

        services.Configure<RateLimiterOptions>(limiter =>
        {
            limiter.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            limiter.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
                IsAccountFormPost(context)
                    ? RateLimitPartition.GetFixedWindowLimiter(
                        "account|" + (context.Connection.RemoteIpAddress?.ToString() ?? "unknown"),
                        _ => new FixedWindowRateLimiterOptions
                        {
                            PermitLimit = permitLimit,
                            Window = window,
                            QueueLimit = 0,
                            AutoReplenishment = true,
                        })
                    : RateLimitPartition.GetNoLimiter("none"));

            // A readable answer for the account pages; the token APIs keep their empty 429.
            var previous = limiter.OnRejected;
            limiter.OnRejected = async (rejected, ct) =>
            {
                if (IsAccountFormPost(rejected.HttpContext))
                {
                    var loc = rejected.HttpContext.RequestServices.GetRequiredService<IStringLocalizer<ShellResource>>();
                    rejected.HttpContext.Response.ContentType = "text/plain; charset=utf-8";
                    await rejected.HttpContext.Response.WriteAsync(loc["Account.TooManyAttempts"].Value, ct);
                    return;
                }

                if (previous is not null)
                {
                    await previous(rejected, ct);
                }
            };
        });

        return services;
    }
}
