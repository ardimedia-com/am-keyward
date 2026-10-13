using Am.Keyward.Client;

namespace Am.Keyward.Mcp;

/// <summary>Elsewhere, or as a fallback: the token from the <c>KEYWARD_AGENT_TOKEN</c> environment variable.</summary>
internal sealed class EnvironmentTokenStore : IKeywardCredentialStore
{
    public const string Variable = "KEYWARD_AGENT_TOKEN";

    public string Place => $"the {Variable} environment variable";

    public string? Read() => Environment.GetEnvironmentVariable(Variable) is { Length: > 0 } token ? token : null;

    public void Write(string token) =>
        throw new PlatformNotSupportedException($"Set the {Variable} environment variable instead.");

    public bool Delete() => false;
}
