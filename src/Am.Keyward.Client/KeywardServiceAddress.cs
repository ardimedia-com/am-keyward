namespace Am.Keyward.Client;

/// <summary>
/// The address of a KEYWARD installation, as every client program treats it: the root URL the user configured, which
/// may carry a sub-path (<c>https://host/app</c>). Shared by the configuration provider, <c>amkeyward-mcp</c> and the
/// <c>keyward</c> CLI so they agree on two things — which addresses are acceptable (HTTPS, or plain HTTP only to this
/// computer) and how API paths and UI links resolve against a sub-path.
/// </summary>
public static class KeywardServiceAddress
{
    /// <summary>
    /// True for <c>https://</c>, and for <c>http://</c> to a loopback host (<c>localhost</c>, <c>127.0.0.1</c>,
    /// <c>[::1]</c>) — a token sent in plain text never leaves this computer.
    /// </summary>
    public static bool IsSecure(Uri address)
    {
        ArgumentNullException.ThrowIfNull(address);
        return address.IsAbsoluteUri
            && (address.Scheme == Uri.UriSchemeHttps || (address.Scheme == Uri.UriSchemeHttp && address.IsLoopback));
    }

    /// <summary>
    /// Parses a configured address. Fails with a message fit for a person when it is not an absolute HTTP(S) URL, or
    /// when it is plain HTTP to another computer (unless <paramref name="allowInsecureHttp"/>).
    /// </summary>
    public static bool TryParse(string? text, out Uri? address, out string? error, bool allowInsecureHttp = false)
    {
        address = null;
        if (string.IsNullOrWhiteSpace(text)
            || !Uri.TryCreate(text.Trim(), UriKind.Absolute, out var parsed)
            || (parsed.Scheme != Uri.UriSchemeHttps && parsed.Scheme != Uri.UriSchemeHttp))
        {
            error = $"'{text}' is not a KEYWARD address - write it as https://keyward.example.com";
            return false;
        }

        if (!allowInsecureHttp && !IsSecure(parsed))
        {
            error = $"'{parsed}' uses plain http to another computer; the token would travel unencrypted. Use https:// (plain http is accepted for localhost only).";
            return false;
        }

        address = parsed;
        error = null;
        return true;
    }

    /// <summary>The installation root, slash-terminated and without query or fragment, so relative paths keep a sub-path.</summary>
    public static Uri Root(Uri address)
    {
        ArgumentNullException.ThrowIfNull(address);
        var path = address.GetLeftPart(UriPartial.Path);
        return new Uri(path.EndsWith('/') ? path : path + "/");
    }

    /// <summary>
    /// A path on the installation (an API base such as <c>/keyward/api/v1</c>, or a UI link such as
    /// <c>/amkeyward/e/…</c>) resolved below <see cref="Root"/>: <c>https://host/app</c> + <c>/amkeyward/e/x</c> →
    /// <c>https://host/app/amkeyward/e/x</c>.
    /// </summary>
    public static Uri Resolve(Uri address, string path)
    {
        ArgumentNullException.ThrowIfNull(path);
        return new Uri(Root(address), path.TrimStart('/'));
    }

    /// <summary>The base URI of an API mapped at <paramref name="apiBasePath"/>, slash-terminated for relative request paths.</summary>
    public static Uri ApiBase(Uri address, string apiBasePath)
    {
        ArgumentNullException.ThrowIfNull(apiBasePath);
        var trimmed = apiBasePath.Trim('/');
        return trimmed.Length == 0 ? Root(address) : new Uri(Root(address), trimmed + "/");
    }
}
