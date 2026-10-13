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
    /// One secret with the reason when there is none — for callers that must say why (a script, the `keyward` CLI):
    /// unknown key, no value in this environment, token rejected or expired (401), caller's network not allowed
    /// (403). Other failures (server error, unreachable) throw <see cref="HttpRequestException"/>.
    /// </summary>
    public async Task<KeywardSecretLookup> LookupAsync(string key, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);

        var escaped = Uri.EscapeDataString(key).Replace("%2F", "/", StringComparison.OrdinalIgnoreCase);
        using var response = await httpClient.GetAsync($"secrets/{escaped}", cancellationToken);
        switch (response.StatusCode)
        {
            case HttpStatusCode.OK:
                var secret = await response.Content.ReadFromJsonAsync<SecretResponse>(cancellationToken);
                return new KeywardSecretLookup(KeywardSecretLookupStatus.Found, secret?.Value);
            case HttpStatusCode.Unauthorized:
                return new KeywardSecretLookup(KeywardSecretLookupStatus.TokenRejected, null);
            case HttpStatusCode.Forbidden:
                return new KeywardSecretLookup(KeywardSecretLookupStatus.NetworkNotAllowed, null);
            case HttpStatusCode.NotFound:
                // Servers before 0.30 send a bare 404; it can only mean «no value» or «no such key».
                var reason = await ReadReasonAsync(response, cancellationToken);
                return new KeywardSecretLookup(
                    reason == KeywardApiDefaults.NoValueReason ? KeywardSecretLookupStatus.NoValue : KeywardSecretLookupStatus.UnknownKey,
                    null);
            default:
                response.EnsureSuccessStatusCode();
                throw new HttpRequestException($"Unexpected response {(int)response.StatusCode}.", null, response.StatusCode);
        }
    }

    private static async Task<string?> ReadReasonAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        try
        {
            using var document = await System.Text.Json.JsonDocument.ParseAsync(
                await response.Content.ReadAsStreamAsync(cancellationToken), cancellationToken: cancellationToken);
            return document.RootElement.TryGetProperty("reason", out var reason) ? reason.GetString() : null;
        }
        catch (System.Text.Json.JsonException)
        {
            return null;
        }
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
