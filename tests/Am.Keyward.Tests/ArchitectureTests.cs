using Am.Keyward.Core.Domain.Identity;
using NetArchTest.Rules;

namespace Am.Keyward.Tests;

[TestClass]
public class ArchitectureTests
{
    /// <summary>
    /// Backstop for the project-boundary purity: the domain must not depend on persistence, hosting,
    /// or crypto. (Core already has no such package references, so this guards future drift.)
    /// </summary>
    [TestMethod, TestCategory("Architecture")]
    public void Domain_has_no_infrastructure_dependencies()
    {
        var result = Types.InAssembly(typeof(Tenant).Assembly)
            .That().ResideInNamespace("Am.Keyward.Core.Domain")
            .ShouldNot().HaveDependencyOnAny(
                "Microsoft.EntityFrameworkCore",
                "Microsoft.AspNetCore",
                "Microsoft.Data.SqlClient",
                "System.Security.Cryptography")
            .GetResult();

        Assert.IsTrue(
            result.IsSuccessful,
            "Domain must stay pure. Offending types: " + string.Join(", ", result.FailingTypeNames ?? []));
    }
}
