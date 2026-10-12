using System.Net;

namespace Am.Keyward.Api;

/// <summary>
/// The host-wide network restriction of the agent API (<see cref="KeywardAgentApiOptions.AllowedNetworks"/>,
/// conventionally <c>Keyward:Agent:AllowedNetworks</c>). See <see cref="KeywardNetworkPolicy"/> for how it is
/// evaluated and what happens with an invalid setting.
/// </summary>
public sealed class AgentNetworkPolicy : KeywardNetworkPolicy
{
    private const string Api = "Keyward agent API";

    /// <summary>
    /// Strict form: parses <paramref name="allowedNetworks"/> and throws <see cref="ArgumentException"/> when it
    /// cannot be used. Hosts that read the setting from configuration should prefer <see cref="Parse"/>, which never
    /// throws (fail closed) — <c>AddKeywardAgentApi</c> does.
    /// </summary>
    public AgentNetworkPolicy(string? allowedNetworks)
        : this(allowedNetworks, knownProxies: null)
    {
        if (Error is not null)
        {
            throw new ArgumentException(Error, nameof(allowedNetworks));
        }
    }

    private AgentNetworkPolicy(string? allowedNetworks, IEnumerable<IPAddress>? knownProxies)
        : base(Api, KeywardAgentApiOptions.AllowedNetworksConfigurationKey, allowedNetworks, knownProxies)
    {
    }

    /// <summary>Parses the setting without throwing: an unusable value yields a policy that refuses every caller.</summary>
    /// <param name="allowedNetworks">Comma- or semicolon-separated CIDR list; null or blank = unrestricted.</param>
    /// <param name="knownProxies">The host's trusted reverse proxies; a setting that contains one is rejected.</param>
    public static AgentNetworkPolicy Parse(string? allowedNetworks, IEnumerable<IPAddress>? knownProxies = null) =>
        new(allowedNetworks, knownProxies);
}
