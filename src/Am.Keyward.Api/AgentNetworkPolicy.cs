using System.Net;

namespace Am.Keyward.Api;

/// <summary>
/// The host-wide network restriction of the agent API (<see cref="KeywardAgentApiOptions.AllowedNetworks"/>): only
/// callers from these networks reach the token check at all. It is evaluated on the address the host sees —
/// behind a reverse proxy that is the proxy, unless the host resolves the real client address (forwarded headers
/// from a known proxy). A proxy address must therefore never be inside an allowed network, or everything it
/// forwards from the internet passes.
/// </summary>
public sealed class AgentNetworkPolicy
{
    private readonly IReadOnlyList<IPNetwork> networks;

    public AgentNetworkPolicy(string? allowedNetworks)
    {
        networks = string.IsNullOrWhiteSpace(allowedNetworks)
            ? []
            : allowedNetworks
                .Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(n => IPNetwork.TryParse(n, out var network)
                    ? network
                    : throw new ArgumentException($"Keyward agent API: '{n}' is not a network in CIDR notation (e.g. 10.1.0.0/23)."))
                .ToList();
    }

    /// <summary>Whether any restriction is configured.</summary>
    public bool IsRestricted => networks.Count > 0;

    public bool Allows(IPAddress? address)
    {
        if (!IsRestricted)
        {
            return true;
        }

        if (address is null)
        {
            return false;
        }

        // A dual-stack socket reports an IPv4 client as IPv4-mapped IPv6 (::ffff:10.1.0.26).
        var ip = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
        return networks.Any(n => n.Contains(ip));
    }
}
