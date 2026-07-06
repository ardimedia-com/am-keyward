using System.Security.Cryptography;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Identity;
using Am.Keyward.Infrastructure;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Am.Keyward.Tests;

/// <summary>
/// The management API gates a caller-supplied {tenantId} on tenant membership. Proves the underlying rule:
/// a member is authorized for their tenant, a non-member is not, a system admin is authorized for any tenant.
/// Runs against a real SQL Server; skips when none is reachable.
/// </summary>
[TestClass]
public class TenantMembershipTests
{
    private static readonly string ConnectionString = TestConfig.ConnectionString;

    [TestMethod, TestCategory("Integration")]
    public async Task Membership_authorizes_member_and_system_admin_but_not_a_non_member()
    {
        await using var provider = BuildProvider();
        using var scope = provider.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
        if (!await db.Database.CanConnectAsync())
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var tenantA = Guid.NewGuid();
        var tenantB = Guid.NewGuid();
        var member = Guid.NewGuid();
        var nonMember = Guid.NewGuid();
        var admin = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;

        db.Users.Add(new AppUser(member, null, member.ToString("D"), "Member", isSystemAdmin: false, now));
        db.Users.Add(new AppUser(nonMember, null, nonMember.ToString("D"), "NonMember", isSystemAdmin: false, now));
        db.Users.Add(new AppUser(admin, null, admin.ToString("D"), "Admin", isSystemAdmin: true, now));
        db.TenantMemberships.Add(new TenantMembership(Guid.NewGuid(), tenantA, member, TenantRole.Member, now));
        await db.SaveChangesAsync();

        var membership = scope.ServiceProvider.GetRequiredService<ITenantMembership>();

        Assert.IsTrue(await membership.IsMemberAsync(member, tenantA), "A member is authorized for their tenant.");
        Assert.IsFalse(await membership.IsMemberAsync(member, tenantB), "A member is not authorized for another tenant.");
        Assert.IsFalse(await membership.IsMemberAsync(nonMember, tenantA), "A non-member is not authorized.");
        Assert.IsTrue(await membership.IsMemberAsync(admin, tenantA), "A system admin is authorized for any tenant.");
        Assert.IsTrue(await membership.IsMemberAsync(admin, tenantB), "A system admin is authorized for any tenant.");
    }

    private static ServiceProvider BuildProvider()
    {
        var services = new ServiceCollection();
        services.AddKeyward(ConnectionString, RandomNumberGenerator.GetBytes(32), "test-kek:v1");
        return services.BuildServiceProvider();
    }
}
