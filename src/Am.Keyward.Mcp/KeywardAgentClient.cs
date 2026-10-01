using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Am.Keyward.Contracts;

namespace Am.Keyward.Mcp;

/// <summary>The outcome of one agent API call: the value on success, otherwise a message fit to show the assistant.</summary>
internal sealed record AgentResult<T>(T? Value, string? Error, HttpStatusCode Status)
{
    public bool Ok => Error is null;
}

/// <summary>
/// Typed HTTP client for the KEYWARD agent API (<c>/keyward/api/v1/agent</c>). The bearer token and base address
/// are set on the <see cref="HttpClient"/> by the host. Errors come back as the server's problem-details title,
/// never as an exception, so a tool can hand them to the assistant as text.
/// </summary>
internal sealed class KeywardAgentClient(HttpClient http)
{
    private const string Prefix = KeywardApiDefaults.BasePath + "/agent";

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public Uri? BaseAddress => http.BaseAddress;

    public Task<AgentResult<object>> PingAsync(CancellationToken ct) => SendAsync<object>(HttpMethod.Get, "/ping", null, null, ct);

    public Task<AgentResult<List<AgentVaultResponse>>> ListVaultsAsync(CancellationToken ct) =>
        SendAsync<List<AgentVaultResponse>>(HttpMethod.Get, "/vaults", null, null, ct);

    public Task<AgentResult<AgentVaultTreeResponse>> TreeAsync(Guid vaultId, CancellationToken ct) =>
        SendAsync<AgentVaultTreeResponse>(HttpMethod.Get, $"/vaults/{vaultId}/tree", null, null, ct);

    public Task<AgentResult<List<AgentItemSummaryResponse>>> SearchAsync(string query, CancellationToken ct) =>
        SendAsync<List<AgentItemSummaryResponse>>(HttpMethod.Get, $"/search?q={Uri.EscapeDataString(query)}", null, null, ct);

    public Task<AgentResult<AgentItemResponse>> GetItemAsync(Guid itemId, CancellationToken ct) =>
        SendAsync<AgentItemResponse>(HttpMethod.Get, $"/items/{itemId}", null, null, ct);

    public Task<AgentResult<AgentItemWrittenResponse>> CreateItemAsync(Guid vaultId, AgentCreateItemRequest body, CancellationToken ct) =>
        SendAsync<AgentItemWrittenResponse>(HttpMethod.Post, $"/vaults/{vaultId}/items", body, null, ct);

    public Task<AgentResult<AgentItemWrittenResponse>> UpdateItemAsync(Guid itemId, Guid versionId, AgentUpdateItemRequest body, CancellationToken ct) =>
        SendAsync<AgentItemWrittenResponse>(HttpMethod.Patch, $"/items/{itemId}", body, versionId, ct);

    public Task<AgentResult<AgentRevealStateResponse>> RequestRevealAsync(Guid itemId, AgentRevealRequestBody body, CancellationToken ct) =>
        SendAsync<AgentRevealStateResponse>(HttpMethod.Post, $"/items/{itemId}/reveal-requests", body, null, ct);

    public Task<AgentResult<AgentRevealStateResponse>> GetRevealAsync(Guid requestId, CancellationToken ct) =>
        SendAsync<AgentRevealStateResponse>(HttpMethod.Get, $"/reveal-requests/{requestId}", null, null, ct);

    public Task<AgentResult<AgentRevealValueResponse>> ConsumeRevealAsync(Guid requestId, CancellationToken ct) =>
        SendAsync<AgentRevealValueResponse>(HttpMethod.Post, $"/reveal-requests/{requestId}/consume", null, null, ct);

    public Task<AgentResult<AgentItemWrittenResponse>> MoveItemAsync(Guid itemId, AgentMoveItemRequest body, CancellationToken ct) =>
        SendAsync<AgentItemWrittenResponse>(HttpMethod.Post, $"/items/{itemId}/move", body, null, ct);

    public Task<AgentResult<List<AgentClientTokenResponse>>> ListApplicationTokensAsync(Guid applicationId, CancellationToken ct) =>
        SendAsync<List<AgentClientTokenResponse>>(HttpMethod.Get, $"/applications/{applicationId}/tokens", null, null, ct);

    public Task<AgentResult<AgentApplicationStatisticsResponse>> GetApplicationStatisticsAsync(Guid applicationId, int days, CancellationToken ct) =>
        SendAsync<AgentApplicationStatisticsResponse>(HttpMethod.Get, $"/applications/{applicationId}/statistics?days={days}", null, null, ct);

    public Task<AgentResult<AgentTokenInfoResponse>> TokenInfoAsync(CancellationToken ct) =>
        SendAsync<AgentTokenInfoResponse>(HttpMethod.Get, "/token", null, null, ct);

    public Task<AgentResult<List<AgentApplicationResponse>>> ListApplicationsAsync(CancellationToken ct) =>
        SendAsync<List<AgentApplicationResponse>>(HttpMethod.Get, "/applications", null, null, ct);

    public Task<AgentResult<AgentApplicationResponse>> GetApplicationAsync(Guid applicationId, CancellationToken ct) =>
        SendAsync<AgentApplicationResponse>(HttpMethod.Get, $"/applications/{applicationId}", null, null, ct);

    public Task<AgentResult<AgentApplicationResponse>> CreateApplicationAsync(AgentCreateApplicationRequest body, CancellationToken ct) =>
        SendAsync<AgentApplicationResponse>(HttpMethod.Post, "/applications", body, null, ct);

    public Task<AgentResult<AgentApplicationResponse>> AddEnvironmentAsync(Guid applicationId, AgentAddEnvironmentRequest body, CancellationToken ct) =>
        SendAsync<AgentApplicationResponse>(HttpMethod.Post, $"/applications/{applicationId}/environments", body, null, ct);

    public Task<AgentResult<AgentSecretWrittenResponse>> CreateSecretAsync(Guid applicationId, AgentCreateSecretRequest body, CancellationToken ct) =>
        SendAsync<AgentSecretWrittenResponse>(HttpMethod.Post, $"/applications/{applicationId}/secrets", body, null, ct);

    /// <summary>
    /// Sets a value: <paramref name="versionId"/> is the value's current version (If-Match), or null while the
    /// environment holds no value yet (If-None-Match: *).
    /// </summary>
    public Task<AgentResult<AgentSecretWrittenResponse>> SetSecretValueAsync(
        Guid applicationId, string key, AgentSetSecretValueRequest body, Guid? versionId, CancellationToken ct) =>
        SendAsync<AgentSecretWrittenResponse>(HttpMethod.Put, $"/applications/{applicationId}/secrets/{Uri.EscapeDataString(key)}", body, versionId, ct,
            ifNoneMatchAny: versionId is null);

    /// <summary>The absolute deep link to an item, for handing to a person.</summary>
    public string AbsoluteLink(string link) =>
        http.BaseAddress is null ? link : new Uri(http.BaseAddress, link).ToString();

    private async Task<AgentResult<T>> SendAsync<T>(
        HttpMethod method, string path, object? body, Guid? ifMatch, CancellationToken ct, bool ifNoneMatchAny = false)
    {
        using var request = new HttpRequestMessage(method, Prefix + path);
        if (body is not null)
        {
            request.Content = JsonContent.Create(body, options: Json);
        }

        if (ifMatch is { } version)
        {
            request.Headers.IfMatch.Add(new EntityTagHeaderValue($"\"{version}\""));
        }

        if (ifNoneMatchAny)
        {
            request.Headers.IfNoneMatch.Add(EntityTagHeaderValue.Any);
        }

        HttpResponseMessage response;
        try
        {
            response = await http.SendAsync(request, ct).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            return new AgentResult<T>(default, $"KEYWARD is not reachable at {http.BaseAddress}: {ex.Message}", 0);
        }

        using (response)
        {
            if (response.IsSuccessStatusCode)
            {
                var value = response.Content.Headers.ContentLength == 0 || response.StatusCode == HttpStatusCode.NoContent
                    ? default
                    : await response.Content.ReadFromJsonAsync<T>(Json, ct).ConfigureAwait(false);
                return new AgentResult<T>(value, null, response.StatusCode);
            }

            return new AgentResult<T>(default, await DescribeAsync(response, ct).ConfigureAwait(false), response.StatusCode);
        }
    }

    private static async Task<string> DescribeAsync(HttpResponseMessage response, CancellationToken ct)
    {
        var status = (int)response.StatusCode;
        var hint = response.StatusCode switch
        {
            HttpStatusCode.Unauthorized => "The agent token was refused (wrong, expired or revoked, or its user is disabled).",
            HttpStatusCode.NotFound => "Not found — or outside what this agent token may reach.",
            HttpStatusCode.Forbidden => "This agent token may not do that.",
            HttpStatusCode.TooManyRequests => "Too many requests; wait a moment.",
            _ => null,
        };

        try
        {
            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
            if (doc.RootElement.TryGetProperty("title", out var title) && title.GetString() is { Length: > 0 } text)
            {
                return $"{status}: {text}";
            }
        }
        catch (JsonException)
        {
            // Not a problem-details body.
        }

        return $"{status}: {hint ?? response.ReasonPhrase}";
    }
}
