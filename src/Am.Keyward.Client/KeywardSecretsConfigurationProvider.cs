using System.Net.Http.Json;
using Microsoft.Extensions.Configuration;

namespace Am.Keyward.Client;

/// <summary>
/// Loads the token's (project, environment) secrets from <c>GET .../secrets</c> into configuration data.
/// The startup load retries (a service booting right after a host reboot must not lose the race against
/// the Keyward server) and fails loudly unless <see cref="KeywardSecretsOptions.Optional"/>; the optional
/// periodic reload keeps the last known good values when a refresh fails.
/// </summary>
public sealed class KeywardSecretsConfigurationProvider : ConfigurationProvider, IDisposable
{
    private readonly KeywardSecretsOptions options;
    private HttpClient? http;
    private CancellationTokenSource? reloadCancellation;

    public KeywardSecretsConfigurationProvider(KeywardSecretsOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        this.options = options;
    }

    public override void Load()
    {
        var token = options.ResolveToken();
        if (string.IsNullOrWhiteSpace(token))
        {
            var variable = options.ResolveTokenVariableName();
            if (options.Optional)
            {
                return; // no token, source stays empty
            }

            throw new InvalidOperationException(
                variable is null
                    ? "No Keyward app token: set KeywardSecretsOptions.Token, TokenEnvironmentVariableName or ApplicationName."
                    : $"No Keyward app token: environment variable '{variable}' is not set (issue a token in Keyward and deploy it with the offered PowerShell block, then restart the service).");
        }

        http = KeywardSecretsClient.CreateHttpClient(options, token!);

        // IConfigurationProvider.Load is synchronous by contract. At host startup there is no sync context,
        // so blocking here cannot deadlock — the same pattern the Azure Key Vault provider uses.
        LoadInitialAsync().GetAwaiter().GetResult();

        if (options.ReloadInterval is { } interval)
        {
            reloadCancellation = new CancellationTokenSource();
            _ = ReloadLoopAsync(interval, reloadCancellation.Token);
        }
    }

    private async Task LoadInitialAsync()
    {
        var delay = options.LoadRetryDelay;
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                Data = await FetchAsync(CancellationToken.None);
                return;
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
            {
                if (attempt < options.LoadRetryCount)
                {
                    await Task.Delay(delay);
                    delay += delay; // double per attempt
                    continue;
                }

                if (options.Optional)
                {
                    return; // unreachable and optional: source stays empty
                }

                throw new InvalidOperationException(
                    $"Could not load the application's secrets from Keyward at '{http!.BaseAddress}' "
                    + $"after {attempt + 1} attempt(s). The app token may be invalid/expired, or the server unreachable.",
                    ex);
            }
        }
    }

    private async Task ReloadLoopAsync(TimeSpan interval, CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(interval);
        while (await TimerTickAsync(timer, cancellationToken))
        {
            try
            {
                var fresh = await FetchAsync(cancellationToken);
                if (!SameData(Data, fresh))
                {
                    Data = fresh;
                    OnReload();
                }
            }
            catch
            {
                // Keep the last known good values; the next tick tries again. There is no logger at the
                // configuration layer, so a transient refresh failure is deliberately silent.
            }
        }
    }

    private static async Task<bool> TimerTickAsync(PeriodicTimer timer, CancellationToken cancellationToken)
    {
        try
        {
            return await timer.WaitForNextTickAsync(cancellationToken);
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }

    private async Task<Dictionary<string, string?>> FetchAsync(CancellationToken cancellationToken)
    {
        var secrets = await http!.GetFromJsonAsync<Dictionary<string, string?>>("secrets", cancellationToken);
        return new Dictionary<string, string?>(secrets ?? [], StringComparer.OrdinalIgnoreCase);
    }

    private static bool SameData(IDictionary<string, string?> current, IDictionary<string, string?> fresh) =>
        current.Count == fresh.Count
        && current.All(kv => fresh.TryGetValue(kv.Key, out var value) && value == kv.Value);

    public void Dispose()
    {
        reloadCancellation?.Cancel();
        reloadCancellation?.Dispose();
        http?.Dispose();
    }
}
