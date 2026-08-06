using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Am.Keyward.Contracts;

namespace Am.Keyward.Client;

/// <summary>
/// Typed HTTP client for the software-client read API. The <see cref="HttpClient"/> must carry the base
/// address (installation root + API base path, slash-terminated) and the Bearer app token — register via
/// <c>AddKeywardSecretsClient</c> (which configures both through <see cref="IHttpClientFactory"/>) for
/// runtime reads; the configuration provider builds its own instance for the startup load. A host without
/// a dependency-injection container (a scheduled task, a small console job) uses
/// <see cref="Create(Action{KeywardSecretsOptions})"/> instead.
/// </summary>
public sealed class KeywardSecretsClient(HttpClient httpClient) : IDisposable
{
    // Non-null only for an instance built by Create(), which therefore owns and disposes it. An injected
    // client belongs to IHttpClientFactory and must survive this object.
    private HttpClient? ownedHttpClient;

    /// <summary>
    /// Builds a self-contained client from the same options and token conventions as
    /// <c>AddKeywardSecretsClient</c>, without needing a service collection — for a scheduled task or
    /// console job that has no host. The instance owns its <see cref="HttpClient"/>, so dispose it.
    /// Throws when no token can be resolved (the environment variable is not set on this machine).
    /// </summary>
    public static KeywardSecretsClient Create(Action<KeywardSecretsOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);

        var options = new KeywardSecretsOptions();
        configure(options);

        var token = options.ResolveToken();
        if (string.IsNullOrWhiteSpace(token))
        {
            var variable = options.ResolveTokenVariableName();
            throw new InvalidOperationException(
                variable is null
                    ? "No Keyward app token: set KeywardSecretsOptions.Token, TokenEnvironmentVariableName or ApplicationName."
                    : $"No Keyward app token: environment variable '{variable}' is not set.");
        }

        var http = CreateHttpClient(options, token);
        return new KeywardSecretsClient(http) { ownedHttpClient = http };
    }

    public void Dispose() => ownedHttpClient?.Dispose();

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

    /// <summary>
    /// Explicit heartbeat: authenticates the token without reading a secret, which counts as a token
    /// access and feeds the server's statistics and heartbeat monitoring. Two uses: a long-running service
    /// that reads its secrets only at startup pings periodically, and a scheduled job pings at the END of a
    /// successful run — which says more than the implicit heartbeat of its startup secret read, because it
    /// proves the run completed rather than merely started.
    /// </summary>
    public async Task PingAsync(CancellationToken cancellationToken = default)
    {
        using var response = await httpClient.GetAsync("ping", cancellationToken);
        response.EnsureSuccessStatusCode();
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
