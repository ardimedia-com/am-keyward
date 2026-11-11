using System.Security.Cryptography;

namespace Am.Keyward.Ui.Blazor.App.Hosting;

/// <summary>
/// Browser hardening headers on every response. A credential manager must never be framed (clickjacking on a
/// reveal or copy button), never run injected script, and never leak its URLs in a Referer.
///
/// <para><b>Content-Security-Policy.</b> Scripts only from this origin plus a per-request nonce, which the one
/// inline script the page needs — the Blazor import map — carries (<see cref="GetNonce"/>, rendered in
/// <c>App.razor</c>). Inline event-handler attributes (<c>onclick="…"</c>) are therefore blocked: wire behaviour
/// through script files instead. Styles allow <c>'unsafe-inline'</c> because the components use <c>style=</c>
/// attributes; that cannot run script. <c>connect-src 'self'</c> covers the Blazor Server WebSocket (same origin).
/// <c>frame-ancestors 'none'</c> and <c>X-Frame-Options: DENY</c> forbid framing.</para>
/// </summary>
public static class SecurityHeaders
{
    private const string NonceItemKey = "Keyward.CspNonce";

    /// <summary>The CSP nonce of the current request (created on first use).</summary>
    public static string GetNonce(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (context.Items[NonceItemKey] is string existing)
        {
            return existing;
        }

        // Hex, not Base64: "+", "/" and "=" would be HTML-encoded in the nonce attribute (&#x2B;), and hex is a valid
        // CSP base64-value.
        var nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
        context.Items[NonceItemKey] = nonce;
        return nonce;
    }

    /// <summary>The Content-Security-Policy for a given nonce.</summary>
    public static string ContentSecurityPolicy(string nonce) =>
        "default-src 'self'; "
        + $"script-src 'self' 'nonce-{nonce}'; "
        + "style-src 'self' 'unsafe-inline'; "
        + "img-src 'self' data: blob:; "
        + "font-src 'self' data:; "
        + "connect-src 'self'; "
        + "object-src 'none'; "
        + "base-uri 'self'; "
        + "form-action 'self'; "
        + "frame-ancestors 'none'";

    /// <summary>Adds the headers to every response (registered early, so error and status pages get them too).</summary>
    public static IApplicationBuilder UseKeywardSecurityHeaders(this IApplicationBuilder app) =>
        app.Use(async (context, next) =>
        {
            var nonce = GetNonce(context);
            context.Response.OnStarting(() =>
            {
                var headers = context.Response.Headers;
                headers.ContentSecurityPolicy = ContentSecurityPolicy(nonce);
                headers.XFrameOptions = "DENY";
                headers.XContentTypeOptions = "nosniff";
                headers["Referrer-Policy"] = "no-referrer";
                headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()";
                headers["Cross-Origin-Opener-Policy"] = "same-origin";
                return Task.CompletedTask;
            });
            await next(context);
        });
}
