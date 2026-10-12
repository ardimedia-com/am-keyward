using System.Net;

namespace Am.Keyward.Api;

/// <summary>
/// A host-wide network restriction of one Keyward API (the agent API: <see cref="AgentNetworkPolicy"/>; the
/// software-client API: <see cref="SoftwareClientNetworkPolicy"/>). Only callers from the configured networks reach
/// the token check at all; everyone else gets 403 with an empty body.
///
/// <para>Evaluated on the address the host sees — <c>HttpContext.Connection.RemoteIpAddress</c>, i.e. AFTER
/// <c>UseForwardedHeaders</c> resolved the real client behind a known proxy. Behind a reverse proxy without
/// forwarded headers that address is the proxy itself, so a proxy address must never lie inside an allowed
/// network, or everything it forwards from the internet passes. A setting that does contain a known proxy
/// (<c>ForwardedHeadersOptions.KnownProxies</c>) is therefore rejected like a malformed one.</para>
///
/// <para>Three states. <b>Unrestricted</b> — no setting: every network passes (<see cref="IsRestricted"/> is
/// false). <b>Restricted</b> — a valid CIDR list. <b>Invalid</b> — a setting that cannot be used: <see cref="Error"/>
/// says why, and <see cref="Allows"/> refuses EVERY caller (fail closed). An invalid setting never throws at
/// startup; it is logged as an error and the API answers 403 until it is corrected.</para>
/// </summary>
public abstract class KeywardNetworkPolicy
{
    private readonly IReadOnlyList<IPNetwork> networks;

    /// <summary>Parses <paramref name="allowedNetworks"/>; never throws (see the class remarks for the states).</summary>
    /// <param name="apiName">The API, for messages ("Keyward agent API").</param>
    /// <param name="settingName">The setting's configuration key, for messages ("Keyward:Agent:AllowedNetworks").</param>
    /// <param name="allowedNetworks">Comma- or semicolon-separated CIDR list; null or blank = unrestricted.</param>
    /// <param name="knownProxies">The host's trusted reverse proxies; none of them may lie inside the networks.</param>
    protected KeywardNetworkPolicy(string apiName, string settingName, string? allowedNetworks, IEnumerable<IPAddress>? knownProxies)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(apiName);
        ArgumentException.ThrowIfNullOrWhiteSpace(settingName);

        ApiName = apiName;
        SettingName = settingName;
        networks = [];

        if (string.IsNullOrWhiteSpace(allowedNetworks))
        {
            return;
        }

        var parsed = new List<IPNetwork>();
        foreach (var entry in allowedNetworks.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!IPNetwork.TryParse(entry, out var network))
            {
                Error = $"{apiName} ({settingName}): '{entry}' is not a network in CIDR notation (e.g. 10.1.0.0/23; a single "
                    + "address is 10.1.0.5/32).";
                return;
            }

            parsed.Add(network);
        }

        if (parsed.Count == 0)
        {
            // Only separators: an empty restriction would read as "no restriction" — treat it as the broken value it is.
            Error = $"{apiName} ({settingName}): the value contains no network.";
            return;
        }

        networks = parsed;

        var admittedProxy = (knownProxies ?? []).FirstOrDefault(p => networks.Any(n => n.Contains(Normalize(p))));
        if (admittedProxy is not null)
        {
            networks = [];
            Error = $"{apiName} ({settingName}): the networks contain the reverse proxy {admittedProxy}; every request it "
                + "forwards from the internet would pass. Keep the proxy's network out of the list.";
        }
    }

    /// <summary>The API this policy guards, for messages.</summary>
    public string ApiName { get; }

    /// <summary>The configuration key the setting is conventionally read from, for messages.</summary>
    public string SettingName { get; }

    /// <summary>Why the setting cannot be used; <c>null</c> when it is valid (or absent). Non-null = fail closed.</summary>
    public string? Error { get; }

    /// <summary>Whether the setting is valid (or absent).</summary>
    public bool IsValid => Error is null;

    /// <summary>Whether callers are restricted at all: a valid network list, or an invalid setting (refuses everyone).</summary>
    public bool IsRestricted => networks.Count > 0 || Error is not null;

    /// <summary>Whether a caller at <paramref name="address"/> may reach the token check. No address = refused when restricted.</summary>
    public bool Allows(IPAddress? address)
    {
        if (Error is not null)
        {
            return false;
        }

        if (networks.Count == 0)
        {
            return true;
        }

        return address is not null && networks.Any(n => n.Contains(Normalize(address)));
    }

    /// <summary>A dual-stack socket (and IIS) report an IPv4 client as IPv4-mapped IPv6 (::ffff:10.1.0.26); compare as IPv4.</summary>
    private static IPAddress Normalize(IPAddress address) => address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
}
