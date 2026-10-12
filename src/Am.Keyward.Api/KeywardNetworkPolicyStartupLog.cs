using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Am.Keyward.Api;

/// <summary>
/// Reports a Keyward API's network restriction once at startup: an ERROR when the setting is unusable (the API then
/// refuses every caller with 403), and — for the software-client API, whose restriction is optional for backward
/// compatibility — a WARNING when there is none. Resolving the policy here also builds it before the first request.
/// </summary>
/// <typeparam name="TPolicy">The policy to report (<see cref="AgentNetworkPolicy"/> or <see cref="SoftwareClientNetworkPolicy"/>).</typeparam>
internal sealed class KeywardNetworkPolicyStartupLog<TPolicy>(TPolicy policy, ILogger<TPolicy> logger) : IHostedService
    where TPolicy : KeywardNetworkPolicy
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        Report(policy, logger);
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <summary>Writes the startup line for <paramref name="networkPolicy"/>; nothing when it is valid and restricted.</summary>
    internal static void Report(KeywardNetworkPolicy networkPolicy, ILogger log)
    {
        if (!networkPolicy.IsValid)
        {
            log.LogError(
                "KEYWARD: {Api} refuses every request (403) until {Setting} is corrected: {Error}",
                networkPolicy.ApiName, networkPolicy.SettingName, networkPolicy.Error);
            return;
        }

        if (!networkPolicy.IsRestricted && networkPolicy is SoftwareClientNetworkPolicy)
        {
            log.LogWarning(
                "KEYWARD: {Setting} is not set — the {Api} accepts app tokens from ANY network that reaches this host. "
                + "Set it to the networks of the deployed applications (comma-separated CIDR list, never the reverse proxy's network).",
                networkPolicy.SettingName, networkPolicy.ApiName);
        }
    }
}
