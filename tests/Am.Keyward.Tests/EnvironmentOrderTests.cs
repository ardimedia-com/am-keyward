using Am.Keyward.Core.Domain;

namespace Am.Keyward.Tests;

/// <summary>
/// The display order of environments must follow the deployment pipeline (Development → Test →
/// Production), not the alphabet. Every row created before the SortOrder column existed carries 0, and
/// nothing in the UI ever writes a different value, so the tie-break IS the effective order in practice.
/// </summary>
[TestClass]
public sealed class EnvironmentOrderTests
{
    [TestMethod]
    [TestCategory("Unit")]
    public void CanonicalRank_OrdersTheBuiltInsAlongThePipeline()
    {
        Assert.IsTrue(EnvironmentOrder.CanonicalRank("Development") < EnvironmentOrder.CanonicalRank("Test"));
        Assert.IsTrue(EnvironmentOrder.CanonicalRank("Test") < EnvironmentOrder.CanonicalRank("Production"));
    }

    [TestMethod]
    [TestCategory("Unit")]
    public void CanonicalRank_PutsAnythingElseAfterTheBuiltIns()
    {
        Assert.IsTrue(EnvironmentOrder.CanonicalRank("Staging") > EnvironmentOrder.CanonicalRank("Production"));
        Assert.IsTrue(EnvironmentOrder.CanonicalRank(null) > EnvironmentOrder.CanonicalRank("Production"));
    }

    [TestMethod]
    [TestCategory("Unit")]
    public void CanonicalRank_IsCaseInsensitive()
    {
        Assert.AreEqual(EnvironmentOrder.CanonicalRank("Development"), EnvironmentOrder.CanonicalRank("development"));
    }

    [TestMethod]
    [TestCategory("Unit")]
    public void AllZeroSortOrder_StillYieldsThePipelineOrder()
    {
        // The state every existing installation is in: the 2026-08-06 backfill matched no rows, so all
        // three rows sit at SortOrder 0 and the tie-break decides.
        (string Name, int SortOrder)[] rows = [("Production", 0), ("Development", 0), ("Test", 0)];

        var ordered = rows
            .OrderBy(r => r.SortOrder)
            .ThenBy(r => EnvironmentOrder.CanonicalRank(r.Name))
            .ThenBy(r => r.Name, StringComparer.OrdinalIgnoreCase)
            .Select(r => r.Name)
            .ToArray();

        CollectionAssert.AreEqual(new[] { "Development", "Test", "Production" }, ordered);
    }

    [TestMethod]
    [TestCategory("Unit")]
    public void AnExplicitSortOrderStillWins()
    {
        (string Name, int SortOrder)[] rows = [("Production", 0), ("Development", 1), ("Test", 2)];

        var ordered = rows
            .OrderBy(r => r.SortOrder)
            .ThenBy(r => EnvironmentOrder.CanonicalRank(r.Name))
            .Select(r => r.Name)
            .ToArray();

        CollectionAssert.AreEqual(new[] { "Production", "Development", "Test" }, ordered);
    }
}
