using Am.Keyward.Ui.Blazor;
using Microsoft.AspNetCore.WebUtilities;

namespace Am.Keyward.Ui.Blazor.App.Identity;

/// <summary>
/// Builds the absolute links that account e-mails carry (confirmation, password reset, invitation) from the
/// configured <c>Keyward:PublicBaseUrl</c> — never from the request's Host header, which a caller controls when
/// <c>AllowedHosts</c> is open and would let them send a victim a reset link pointing at their own server.
/// Outside Development the base URL is mandatory (the startup validation enforces it); only Development falls back
/// to the address the browser used.
/// </summary>
public sealed class AccountLinkBuilder(KeywardUiOptions uiOptions, IHostEnvironment environment)
{
    /// <summary>
    /// The absolute link to <paramref name="relativePath"/> (e.g. <c>account/reset-password</c>) with
    /// <paramref name="query"/> appended.
    /// </summary>
    /// <param name="relativePath">Path relative to the site root.</param>
    /// <param name="query">Query parameters (values are URL-encoded).</param>
    /// <param name="developmentFallbackBase">The request's base URI; used only in Development without a configured base.</param>
    /// <exception cref="InvalidOperationException">No public base URL outside Development.</exception>
    public string Build(string relativePath, IReadOnlyDictionary<string, string?> query, string? developmentFallbackBase = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(relativePath);

        var baseUrl = uiOptions.PublicBaseUrl;
        if (string.IsNullOrWhiteSpace(baseUrl))
        {
            if (!environment.IsDevelopment() || string.IsNullOrWhiteSpace(developmentFallbackBase))
            {
                throw new InvalidOperationException(
                    "Keyward:PublicBaseUrl is not configured; refusing to build an account link from the request host.");
            }

            baseUrl = developmentFallbackBase;
        }

        var link = baseUrl.TrimEnd('/') + "/" + relativePath.TrimStart('/');
        return QueryHelpers.AddQueryString(link, query);
    }
}
