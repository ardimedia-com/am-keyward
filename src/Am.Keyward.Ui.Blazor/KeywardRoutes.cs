namespace Am.Keyward.Ui.Blazor;

/// <summary>
/// Canonical route paths for the embedded Keyward feature pages. All live under the <see cref="Prefix"/>
/// namespace so they cannot collide with a host app's own routes. Use these constants for links and
/// navigation instead of hardcoding strings. NOTE: Blazor's <c>@page</c> directive needs a literal, so the
/// route literals in the page files must be kept in sync with these constants (they share the prefix).
/// </summary>
public static class KeywardRoutes
{
    /// <summary>The route namespace every Keyward page sits under (mirrors the API's <c>/keyward</c> and the asset path).</summary>
    public const string Prefix = "/amkeyward";

    public const string PersonalVaults = Prefix + "/vaults/personal";
    public const string TeamVaults = Prefix + "/vaults/team";
    public const string Vaults = Prefix + "/vaults";
    public const string Applications = Prefix + "/applications";
    public const string SoftwareCredentials = Prefix + "/secrets";
    public const string ClientTokens = Prefix + "/tokens";
    public const string Groups = Prefix + "/groups";
    public const string DefaultEnvironments = Prefix + "/default-environments";
}
