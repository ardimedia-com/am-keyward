namespace Am.Keyward.Core.Domain;

/// <summary>
/// The canonical display order of the built-in environments. <c>SortOrder</c> remains the primary key of
/// the ordering (it carries a deliberate order where one exists); this is the TIE-BREAK below it, used
/// instead of the alphabet.
/// <para>
/// It matters because a tie is the normal state, not an edge case: every row created before
/// <c>20260806122206_EnvironmentSortOrder</c> carries SortOrder 0, and there is no UI to reorder
/// environments, so nothing ever writes a different value. Sorting by name then yields «Development,
/// Production, Test» — alphabetical, and wrong for a deployment pipeline that runs Development → Test →
/// Production.
/// </para>
/// </summary>
public static class EnvironmentOrder
{
    /// <summary>Rank of a built-in environment name; anything else sorts after them, then by name.</summary>
    public static int CanonicalRank(string? name) =>
        string.Equals(name, "Development", StringComparison.OrdinalIgnoreCase) ? 0
        : string.Equals(name, "Test", StringComparison.OrdinalIgnoreCase) ? 1
        : string.Equals(name, "Production", StringComparison.OrdinalIgnoreCase) ? 2
        : 3;
}
