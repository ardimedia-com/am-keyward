namespace Am.Keyward.Ui.Blazor;

/// <summary>
/// Decides whether a stored address (a login's URL — text anyone with write access to the vault can set) may become a
/// clickable link. Only absolute <c>http</c> / <c>https</c> addresses qualify; <c>javascript:</c>, <c>data:</c>,
/// <c>file:</c>, relative paths and anything unparsable stay plain text.
/// </summary>
internal static class SafeHttpLink
{
    /// <summary>The address to put into <c>href</c>, or null when it must not be a link.</summary>
    public static string? ForHref(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)
            || !Uri.TryCreate(url.Trim(), UriKind.Absolute, out var uri)
            || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            return null;
        }

        return uri.AbsoluteUri;
    }
}
