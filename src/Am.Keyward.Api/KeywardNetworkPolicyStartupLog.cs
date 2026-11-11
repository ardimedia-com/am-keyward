using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Am.Keyward.Api;

/// <summary>
/// Reports a Keyward API's network restriction once at startup: an ERROR when the setting is unusable (the API then
/// refuses every caller with 403), a WARNING when there is none (both APIs: the restriction is optional for backward
/// compatibility, but an unrestricted credential API answers every network that reaches the host), and a note when the
/// API is restricted but the host configured no trusted proxy — the «list contains the proxy» guard is then blind.
/// Resolving the policy here also builds it before the first request.
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

        if (!networkPolicy.IsRestricted)
        {
            var callers = networkPolicy is AgentNetworkPolicy
                ? "agent tokens (AI assistants acting for their users)"
                : "app tokens";
            log.LogWarning(
                "KEYWARD: {Setting} is not set — the {Api} accepts {Callers} from ANY network that reaches this host. "
                + "Set it to the networks the callers sit in (comma-separated CIDR list, never the reverse proxy's network).",
                networkPolicy.SettingName, networkPolicy.ApiName, callers);
            return;
        }

        if (!networkPolicy.ProxyGuardActive)
        {
            log.LogInformation(
                "KEYWARD: {Api} is restricted by {Setting}, but the host configured no trusted proxy "
                + "(ForwardedHeadersOptions.KnownProxies / KnownIPNetworks). Behind a reverse proxy, configure UseForwardedHeaders "
                + "with that proxy — otherwise every request carries the proxy's address and the restriction cannot tell callers apart, "
                + "and a list that contains the proxy cannot be detected.",
                networkPolicy.ApiName, networkPolicy.SettingName);
        }
    }
}
