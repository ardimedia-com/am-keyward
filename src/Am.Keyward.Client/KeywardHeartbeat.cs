using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Am.Keyward.Client;

/// <summary>
/// One-call heartbeat for a scheduled job: reports a completed run to the installation's monitoring, and
/// never lets that reporting break the run. Monitoring exists for the failure a job cannot report itself —
/// a process that never starts sends no error mail — so the call is deliberately best-effort: an
/// unconfigured service URI means monitoring is off for this environment, and any failure (no token,
/// server unreachable, revoked token) is logged and swallowed. The missing ping is itself the signal, and
/// it clears on the next successful run.
///
/// Call it at the END of a run that completed: that proves the run finished, whereas the implicit
/// heartbeat of a startup secret read only proves it began.
/// </summary>
public static class KeywardHeartbeat
{
    /// <summary>The conventional configuration key holding the installation's root URL.</summary>
    public const string ServiceUriConfigurationKey = "Keyward:ServiceUri";

    /// <summary>
    /// Pings the installation configured under <see cref="ServiceUriConfigurationKey"/>. An absent or empty
    /// value means monitoring is not configured for this environment (the usual local-development case) and
    /// the call does nothing. Returns whether a heartbeat actually reached the server.
    /// </summary>
    public static Task<bool> SendAsync(
        IConfiguration configuration,
        string applicationName,
        ILogger? logger = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var configured = configuration[ServiceUriConfigurationKey];
        var serviceUri = string.IsNullOrWhiteSpace(configured) ? null : new Uri(configured, UriKind.Absolute);
        return SendAsync(serviceUri, applicationName, logger, cancellationToken);
    }

    /// <summary>
    /// Pings <paramref name="serviceUri"/> for the application whose token this machine holds in the
    /// conventional environment variable (<c>Contoso.Nightly.Sync</c> →
    /// <c>KEYWARD_CONTOSO_NIGHTLY_SYNC_TOKEN</c>). A null <paramref name="serviceUri"/> means monitoring is
    /// not configured and the call does nothing. Returns whether a heartbeat actually reached the server.
    /// </summary>
    public static Task<bool> SendAsync(
        Uri? serviceUri,
        string applicationName,
        ILogger? logger = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(applicationName);

        if (serviceUri is null)
        {
            (logger ?? NullLogger.Instance).LogDebug("Keyward heartbeat skipped — no service URI configured for this environment.");
            return Task.FromResult(false);
        }

        return SendAsync(
            options =>
            {
                options.ServiceUri = serviceUri;
                options.ApplicationName = applicationName;
            },
            logger,
            cancellationToken);
    }

    /// <summary>
    /// The explicit form: full control over the client options (an explicit token, a custom timeout, a
    /// proxy handler). Same best-effort contract — it reports failure instead of throwing.
    /// </summary>
    public static async Task<bool> SendAsync(
        Action<KeywardSecretsOptions> configure,
        ILogger? logger = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(configure);

        var log = logger ?? NullLogger.Instance;
        string? applicationName = null;
        try
        {
            using var client = KeywardSecretsClient.Create(options =>
            {
                configure(options);
                applicationName = options.ApplicationName;
            });

            await client.PingAsync(cancellationToken).ConfigureAwait(false);
            log.LogInformation("Keyward heartbeat sent for {Application}", applicationName ?? "(unnamed)");
            return true;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw; // the caller is shutting down — not a monitoring failure to swallow
        }
        catch (Exception ex)
        {
            // Never fail the job over its own monitoring; the absent heartbeat is the signal.
            log.LogWarning(ex, "Keyward heartbeat failed for {Application} — the run itself was not affected", applicationName ?? "(unnamed)");
            return false;
        }
    }
}
