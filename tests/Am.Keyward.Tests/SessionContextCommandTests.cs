using Am.Keyward.Infrastructure.Persistence;
using Microsoft.Data.SqlClient;
using System.Data;

namespace Am.Keyward.Tests;

/// <summary>
/// Guards the one property that keeps production alive on an unpatched SQL Server: the session-context
/// statement must NEVER write a NULL value. Repeatedly setting a session-context key to NULL leaks memory
/// on builds without the KB4089324 fix (SQL Server 2017 &lt; CU6 / 2016 SP1 &lt; CU8 — the RTM-GDR branch
/// 14.0.2xxx never receives it), until every statement on that pooled connection dies with error 15665.
/// That is what took AM KEYWARD down on 2026-08-07: ~415 minutes of a 60-second tenant-less background
/// timer after a deploy restart were enough to fill the 1 MB session-context budget.
/// </summary>
[TestClass]
public sealed class SessionContextCommandTests
{
    private static readonly Guid Tenant = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid User = Guid.Parse("22222222-2222-2222-2222-222222222222");

    [TestMethod]
    [TestCategory("Unit")]
    public void TryPrepare_NoValueIsEverNull()
    {
        // Every combination, including the all-null one that the background services produce.
        foreach (Guid? tenant in new Guid?[] { null, Tenant })
        {
            foreach (Guid? user in new Guid?[] { null, User })
            {
                foreach (bool? bypass in new bool?[] { null, false, true })
                {
                    using var command = new SqlCommand();
                    SessionContextCommand.TryPrepare(command, tenant, user, bypass);

                    foreach (SqlParameter parameter in command.Parameters)
                    {
                        Assert.AreNotEqual(
                            DBNull.Value,
                            parameter.Value,
                            $"{parameter.ParameterName} was sent as NULL (tenant={tenant}, user={user}, bypass={bypass}) — "
                            + "that is the KB4089324 leak path.");
                    }
                }
            }
        }
    }

    [TestMethod]
    [TestCategory("Unit")]
    public void TryPrepare_OmitsTheKeyInsteadOfSettingItNull()
    {
        using var command = new SqlCommand();
        bool any = SessionContextCommand.TryPrepare(command, tenantId: null, userId: null, systemBypass: false);

        Assert.IsTrue(any, "SystemBypass alone still has to be written.");
        StringAssert.Contains(command.CommandText, "SystemBypass");
        Assert.IsFalse(command.CommandText.Contains("TenantId"), "A null tenant must not appear in the statement at all.");
        Assert.IsFalse(command.CommandText.Contains("UserId"), "A null user must not appear in the statement at all.");
    }

    [TestMethod]
    [TestCategory("Unit")]
    public void TryPrepare_NothingToSet_SkipsTheRoundTrip()
    {
        using var command = new SqlCommand();
        bool any = SessionContextCommand.TryPrepare(command, tenantId: null, userId: null, systemBypass: null);

        Assert.IsFalse(any, "With nothing to set the caller must be able to skip the command entirely.");
        Assert.AreEqual(string.Empty, command.CommandText);
    }

    [TestMethod]
    [TestCategory("Unit")]
    public void TryPrepare_WritesBothScopeKeysWhenPresent()
    {
        using var command = new SqlCommand();
        bool any = SessionContextCommand.TryPrepare(command, Tenant, User, systemBypass: true);

        Assert.IsTrue(any);
        StringAssert.Contains(command.CommandText, "TenantId");
        StringAssert.Contains(command.CommandText, "UserId");
        StringAssert.Contains(command.CommandText, "SystemBypass");
        Assert.AreEqual(Tenant, command.Parameters["@tenant"].Value);
        Assert.AreEqual(User, command.Parameters["@user"].Value);
        Assert.AreEqual(1, command.Parameters["@bypass"].Value);
    }
}
