using System.Net;

namespace Am.Keyward.Api;

/// <summary>
/// The host-wide network restriction of the software-client API (<see cref="KeywardSoftwareClientApiOptions.AllowedNetworks"/>,
/// conventionally <c>Keyward:Client:AllowedNetworks</c>): only deployed applications in these networks reach the
/// token check of <c>/keyward/api/v1/secrets</c> and <c>/ping</c>. Without the setting the API stays reachable from
/// every network (as before), and a warning is logged at startup. See <see cref="KeywardNetworkPolicy"/> for how it
/// is evaluated and what happens with an invalid setting.
/// </summary>
public sealed class SoftwareClientNetworkPolicy : KeywardNetworkPolicy
{
    private const string Api = "Keyward software-client API";

    private SoftwareClientNetworkPolicy(string? allowedNetworks, IEnumerable<IPAddress>? knownProxies)
        : base(Api, KeywardSoftwareClientApiOptions.AllowedNetworksConfigurationKey, allowedNetworks, knownProxies)
    {
    }

    /// <summary>Parses the setting without throwing: an unusable value yields a policy that refuses every caller.</summary>
    /// <param name="allowedNetworks">Comma- or semicolon-separated CIDR list; null or blank = unrestricted.</param>
    /// <param name="knownProxies">The host's trusted reverse proxies; a setting that contains one is rejected.</param>
    public static SoftwareClientNetworkPolicy Parse(string? allowedNetworks, IEnumerable<IPAddress>? knownProxies = null) =>
        new(allowedNetworks, knownProxies);
}
