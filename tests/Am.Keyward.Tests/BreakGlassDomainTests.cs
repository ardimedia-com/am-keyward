using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Access;
using Am.Keyward.Core.Domain.ValueObjects;

namespace Am.Keyward.Tests;

/// <summary>
/// Break-glass dual control is enforced in the domain: a request cannot be self-approved, and a grant is
/// only consumable while approved and unexpired.
/// </summary>
[TestClass]
public class BreakGlassDomainTests
{
    private static readonly DateTimeOffset T0 = new(2026, 6, 22, 10, 0, 0, TimeSpan.Zero);

    private static BreakGlassGrant NewGrant(Guid requester) =>
        new(Guid.NewGuid(), Guid.NewGuid(), new GrantScope(GrantScopeKind.Vault, Guid.NewGuid()),
            requester, "incident-1234", T0, T0.AddHours(1));

    [TestMethod, TestCategory("Unit")]
    public void Requester_cannot_self_approve()
    {
        var requester = Guid.NewGuid();
        var grant = NewGrant(requester);
        Assert.ThrowsExactly<InvalidOperationException>(() => grant.Approve(requester, T0));
    }

    [TestMethod, TestCategory("Unit")]
    public void A_different_admin_can_approve_and_the_grant_becomes_usable()
    {
        var grant = NewGrant(Guid.NewGuid());
        grant.Approve(Guid.NewGuid(), T0);
        Assert.AreEqual(BreakGlassStatus.Approved, grant.Status);
        Assert.IsTrue(grant.IsUsable(T0.AddMinutes(30)));
    }

    [TestMethod, TestCategory("Unit")]
    public void Pending_grant_cannot_be_consumed()
    {
        var grant = NewGrant(Guid.NewGuid());
        Assert.ThrowsExactly<InvalidOperationException>(() => grant.Consume(T0));
    }

    [TestMethod, TestCategory("Unit")]
    public void Approved_grant_consumes_once_then_is_spent()
    {
        var grant = NewGrant(Guid.NewGuid());
        grant.Approve(Guid.NewGuid(), T0);
        grant.Consume(T0.AddMinutes(5));
        Assert.AreEqual(BreakGlassStatus.Consumed, grant.Status);
        Assert.ThrowsExactly<InvalidOperationException>(() => grant.Consume(T0.AddMinutes(6)));
    }

    [TestMethod, TestCategory("Unit")]
    public void Expired_grant_cannot_be_consumed()
    {
        var grant = NewGrant(Guid.NewGuid());
        grant.Approve(Guid.NewGuid(), T0);
        Assert.IsFalse(grant.IsUsable(T0.AddHours(2)));
        Assert.ThrowsExactly<InvalidOperationException>(() => grant.Consume(T0.AddHours(2)));
        Assert.AreEqual(BreakGlassStatus.Expired, grant.Status);
    }
}
