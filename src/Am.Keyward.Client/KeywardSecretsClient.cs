using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Am.Keyward.Contracts;

namespace Am.Keyward.Client;

/// <summary>
/// Typed HTTP client for the software-client read API. The <see cref="HttpClient"/> must carry the base
/// address (installation root + API base path, slash-terminated) and the Bearer app token — register via
/// <c>AddKeywardSecretsClient</c> (which configures both through <see cref="IHttpClientFactory"/>) for
/// runtime reads; the configuration provider builds its own instance for the startup load.
/// </summary>
public sealed class KeywardSecretsClient(HttpClient httpClient)
{
    /// <summary>All current key/value pairs of the token's (project, environment) — the bulk read.</summary>
    public async Task<IReadOnlyDictionary<string, string?>> GetAllAsync(CancellationToken cancellationToken = default) =>
        await httpClient.GetFromJsonAsync<Dictionary<string, string?>>("secrets", cancellationToken)
        ?? [];

    /// <summary>One secret by key (e.g. <c>ConnectionStrings:Main</c>), or null when the key does not exist.</summary>
    public async Task<string?> GetAsync(string key, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);

        // Escape the key for the URL path, but keep '/' literal — the server route is a {**key} catch-all,
        // so hierarchical keys travel as path segments.
        var escaped = Uri.EscapeDataString(key).Replace("%2F", "/", StringComparison.OrdinalIgnoreCase);
        using var response = await httpClient.GetAsync($"secrets/{escaped}", cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }

        response.EnsureSuccessStatusCode();
        var secret = await response.Content.ReadFromJsonAsync<SecretResponse>(cancellationToken);
        return secret?.Value;
    }

    /// <summary>Builds the standalone <see cref="HttpClient"/> the configuration provider uses (it owns and disposes it).</summary>
    internal static HttpClient CreateHttpClient(KeywardSecretsOptions options, string token)
    {
        var http = options.HttpMessageHandler is { } handler
            ? new HttpClient(handler, disposeHandler: true)
            : new HttpClient();
        http.BaseAddress = options.ResolveApiBaseUri();
        http.Timeout = options.RequestTimeout;
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return http;
    }
}
