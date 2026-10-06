using System.Text;
using Am.Keyward.Contracts;

namespace Am.Keyward.Mcp;

/// <summary>What <c>amkeyward-mcp check</c> prints about the token: its permissions and what it reaches.</summary>
internal static class CheckReport
{
    private static readonly Dictionary<string, string> PermissionNames = new()
    {
        ["VaultList"] = "list entries",
        ["VaultRead"] = "read URL and user name",
        ["VaultWrite"] = "create and update entries",
        ["VaultReveal"] = "ask to see a secret",
        ["TotpCodes"] = "get one-time codes (2FA) directly",
        ["ManageApplications"] = "manage applications",
    };

    public static string Describe(AgentTokenInfoResponse info)
    {
        var permissions = info.Permissions.Select(p => PermissionNames.GetValueOrDefault(p, p));
        var text = new StringBuilder()
            .AppendLine($"Token «{info.Name}», valid until {info.ExpiresAt:yyyy-MM-dd} (UTC).")
            .AppendLine($"Permissions: {string.Join(", ", permissions)}.")
            .AppendLine(info.AllAgentVaults ? "Vaults: all vaults opened to agents (also future ones)." : $"Vaults: {info.VaultCount}.");
        if (info.Permissions.Contains("ManageApplications"))
        {
            text.AppendLine(info.AllApplications
                ? "Applications: all (also future ones)."
                : $"Applications: {info.ApplicationCount}{(info.MayCreateApplications ? ", and may create new ones" : "")}.");
        }

        text.Append(string.IsNullOrEmpty(info.AllowedNetworks) ? "Networks: any." : $"Networks: {info.AllowedNetworks}.");
        return text.ToString();
    }
}
