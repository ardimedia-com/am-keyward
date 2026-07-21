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

    /// <summary>Short, shareable deep link to a single vault item: <c>/amkeyward/e/{base62-public-id}</c>. The
    /// <see cref="EntryLink"/> page resolves it and forwards to the right vault page with the item opened.</summary>
    public const string EntryLink = Prefix + "/e";

    /// <summary>Builds the deep-link path for an item's Base62 public id (see <see cref="EntryLink"/>).</summary>
    public static string EntryLinkFor(string publicIdCode) => $"{EntryLink}/{publicIdCode}";

    /// <summary>Query-parameter name the vault pages read to open an item by its Base62 public id.</summary>
    public const string ItemQueryParam = "item";
    // Software side, consolidated 2026-07-21: applications, their per-environment data (secrets) and client
    // tokens all live under Applications now — the former /secrets and /tokens routes were removed.
    public const string Applications = Prefix + "/applications";
    public const string Groups = Prefix + "/groups";
    public const string DefaultEnvironments = Prefix + "/default-environments";
    public const string BreakGlass = Prefix + "/breakglass";
}
