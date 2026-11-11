using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Am.Keyward.Client;

/// <summary>
/// Loads the token's (project, environment) secrets from <c>GET .../secrets</c> into configuration data.
/// The startup load retries (a service booting right after a host reboot must not lose the race against
/// the Keyward server) within <see cref="KeywardSecretsOptions.StartupTimeout"/> and fails loudly unless
/// <see cref="KeywardSecretsOptions.Optional"/>; a token the server rejects (401/403) is not retried. The optional
/// periodic reload keeps the last known good values when a refresh fails.
/// </summary>
public sealed class KeywardSecretsConfigurationProvider : ConfigurationProvider, IDisposable
{
    private readonly KeywardSecretsOptions options;
    private readonly Lock gate = new();
    private HttpClient? http;
    private CancellationTokenSource? reloadCancellation;
    private bool initialized;
    private bool disposed;
    private bool reloadFailing;
    private bool reloadRejected;

    public KeywardSecretsConfigurationProvider(KeywardSecretsOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        this.options = options;
    }

    /// <summary>
    /// The first call is the startup load (retries, deadline, fails loudly unless optional). A later call — an explicit
    /// <c>IConfigurationRoot.Reload()</c> — refreshes once with the same client and keeps the last known good values on
    /// failure; it never creates a second client or a second reload loop.
    /// </summary>
    public override void Load()
    {
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (!initialized || http is null)
            {
                // IConfigurationProvider.Load is synchronous by contract. At host startup there is no sync context,
                // so blocking here cannot deadlock — the same pattern the Azure Key Vault provider uses.
                LoadInitial();
                initialized = true;
            }
            else
            {
                try
                {
                    Data = FetchAsync(http, CancellationToken.None).GetAwaiter().GetResult();
                }
                catch (Exception ex) when (IsLoadFailure(ex))
                {
                    ReportReloadFailure(ex);
                }
            }

            if (http is not null && options.ReloadInterval is { } interval && reloadCancellation is null)
            {
                reloadCancellation = new CancellationTokenSource();
                _ = ReloadLoopAsync(interval, reloadCancellation.Token);
            }
        }
    }

    private void LoadInitial()
    {
        var token = options.ResolveToken();
        if (string.IsNullOrWhiteSpace(token))
        {
            if (options.Optional)
            {
                return; // no token, source stays empty
            }

            var variable = options.ResolveTokenVariableName();
            throw new InvalidOperationException(
                variable is null
                    ? "No Keyward app token: set KeywardSecretsOptions.Token, TokenEnvironmentVariableName or ApplicationName."
                    : $"No Keyward app token: environment variable '{variable}' is not set (issue a token in Keyward and deploy it with the offered PowerShell block, then restart the service).");
        }

        var client = KeywardSecretsClient.CreateHttpClient(options, token!);
        http = client;

        using var deadline = new CancellationTokenSource(options.StartupTimeout);
        var delay = options.LoadRetryDelay;
        for (var attempt = 0; ; attempt++)
        {
            Exception failure;
            try
            {
                Data = FetchAsync(client, deadline.Token).GetAwaiter().GetResult();
                return;
            }
            catch (Exception ex) when (IsLoadFailure(ex))
            {
                failure = ex;
            }

            // A rejected token stays rejected: retrying only feeds the server's failed-authentication throttle.
            var rejected = IsRejected(failure);
            if (!rejected && attempt < options.LoadRetryCount && !deadline.IsCancellationRequested && Wait(delay, deadline.Token))
            {
                delay += delay; // double per attempt
                continue;
            }

            if (options.Optional)
            {
                return; // unreachable or rejected, and optional: source stays empty
            }

            var reason = rejected
                ? $"Keyward rejected the app token ({(int)((HttpRequestException)failure).StatusCode!}) — it is unknown, revoked or expired, or this network may not use the API."
                : deadline.IsCancellationRequested
                    ? $"Keyward did not answer within {options.StartupTimeout.TotalSeconds:0} seconds (KeywardSecretsOptions.StartupTimeout)."
                    : "The app token may be invalid/expired, or the server unreachable or not a Keyward server.";
            throw new InvalidOperationException(
                $"Could not load the application's secrets from Keyward at '{client.BaseAddress}' after {attempt + 1} attempt(s). {reason}",
                failure);
        }
    }

    private static bool Wait(TimeSpan delay, CancellationToken cancellationToken)
    {
        try
        {
            Task.Delay(delay, cancellationToken).GetAwaiter().GetResult();
            return true;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }

    private async Task ReloadLoopAsync(TimeSpan interval, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                // ±10 % jitter, so many instances started together do not refresh in lockstep.
                await Task.Delay(Jittered(interval), cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            if (http is not { } client)
            {
                continue;
            }

            try
            {
                var fresh = await FetchAsync(client, cancellationToken).ConfigureAwait(false);
                ReportReloadRecovered();
                bool changed;
                lock (gate)
                {
                    changed = !SameData(Data, fresh);
                    if (changed)
                    {
                        Data = fresh;
                    }
                }

                if (changed)
                {
                    OnReload();
                }
            }
            catch (Exception) when (cancellationToken.IsCancellationRequested)
            {
                return; // disposed while a refresh was in flight
            }
            catch (Exception ex) when (IsLoadFailure(ex))
            {
                // Keep the last known good values; the next tick tries again.
                ReportReloadFailure(ex);
            }
        }
    }

    internal static TimeSpan Jittered(TimeSpan interval)
    {
        var factor = 0.9 + (Random.Shared.NextDouble() * 0.2);
        return TimeSpan.FromTicks(Math.Max(TimeSpan.TicksPerMillisecond, (long)(interval.Ticks * factor)));
    }

    // Reported on the transition only, so a long outage writes one line, not one per tick.
    private void ReportReloadFailure(Exception ex)
    {
        if (IsRejected(ex))
        {
            if (reloadRejected)
            {
                return;
            }

            reloadRejected = reloadFailing = true;
            var status = (int)((HttpRequestException)ex).StatusCode!;
            if (options.Logger is { } logger)
            {
                logger.LogError(ex, "Keyward rejected the app token ({Status}) while reloading secrets from {Address}; the last loaded values stay in use until a valid token is deployed.", status, http?.BaseAddress);
            }
            else
            {
                Console.Error.WriteLine($"Keyward: the app token was rejected ({status}) while reloading secrets from {http?.BaseAddress}; the last loaded values stay in use.");
            }

            return;
        }

        if (!reloadFailing)
        {
            reloadFailing = true;
            options.Logger?.LogWarning(ex, "Reloading secrets from Keyward at {Address} failed; the last loaded values stay in use.", http?.BaseAddress);
        }
    }

    private void ReportReloadRecovered()
    {
        if (reloadFailing)
        {
            reloadFailing = reloadRejected = false;
            options.Logger?.LogInformation("Reloading secrets from Keyward at {Address} works again.", http?.BaseAddress);
        }
    }

    // Everything a bad answer can throw: unreachable, timed out, an error status, or a body that is not the JSON object
    // (an HTML error or login page answered with 200).
    private static bool IsLoadFailure(Exception ex) =>
        ex is HttpRequestException or OperationCanceledException or JsonException or NotSupportedException;

    private static bool IsRejected(Exception ex) =>
        ex is HttpRequestException { StatusCode: HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden };

    private static async Task<Dictionary<string, string?>> FetchAsync(HttpClient client, CancellationToken cancellationToken)
    {
        var secrets = await client.GetFromJsonAsync<Dictionary<string, string?>>("secrets", cancellationToken).ConfigureAwait(false);
        return new Dictionary<string, string?>(secrets ?? [], StringComparer.OrdinalIgnoreCase);
    }

    private static bool SameData(IDictionary<string, string?> current, IDictionary<string, string?> fresh) =>
        current.Count == fresh.Count
        && current.All(kv => fresh.TryGetValue(kv.Key, out var value) && value == kv.Value);

    public void Dispose()
    {
        lock (gate)
        {
            if (disposed)
            {
                return;
            }

            disposed = true;
            reloadCancellation?.Cancel();
            reloadCancellation?.Dispose();
            http?.Dispose();
        }
    }
}
