using System.Security.Cryptography;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Identity;
using Am.Keyward.Infrastructure;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.Extensions.DependencyInjection;

namespace Am.Keyward.Tests;

/// <summary>
/// Tenant groups end-to-end: lifecycle is restricted to tenant admins, membership management works, a
/// vault shared with a GROUP is visible/readable for the group's members, and revoking the group's grant
/// (or leaving the group) takes the access away again. Runs against a real SQL Server; skips when none.
/// </summary>
[TestClass]
public class GroupsIntegrationTests
{
    private static readonly string ConnectionString = TestConfig.ConnectionString;

    [TestMethod, TestCategory("Integration")]
    public async Task Group_shared_vault_is_accessible_to_members_until_revoked()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var tenantId = Guid.NewGuid();
        var admin = Guid.NewGuid();   // tenant admin
        var member = Guid.NewGuid();  // plain member, gets access via the group
        var outsider = Guid.NewGuid();

        await SeedTenantAsync(provider, tenantId,
            (admin, TenantRole.TenantAdmin), (member, TenantRole.Member), (outsider, TenantRole.Member));

        Guid groupId, vaultId, itemId;
        using (var scope = ScopeFor(provider, admin, tenantId))
        {
            var groups = scope.ServiceProvider.GetRequiredService<IGroupService>();
            var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();

            groupId = await groups.CreateGroupAsync(admin, tenantId, "IT");
            await groups.AddMemberAsync(admin, tenantId, groupId, member, GroupRole.Member);
            Assert.HasCount(1, await groups.ListMembersAsync(admin, tenantId, groupId));

            vaultId = await vaults.CreateTenantVaultAsync(new CreateTenantVaultCommand(admin, tenantId, "Infra"));
            itemId = await vaults.AddItemAsync(new AddVaultItemCommand(admin, vaultId, null, ItemType.SecureNote, "WifiKey", "group-secret"));
            await vaults.ShareWithGroupAsync(new ShareVaultWithGroupCommand(admin, tenantId, vaultId, groupId, Permission.Read));

            var shares = await vaults.ListVaultSharesAsync(admin, vaultId);
            Assert.IsTrue(shares.Any(s => s.PrincipalType == PrincipalType.Group && s.PrincipalId == groupId));
        }

        // The group member sees the vault and can read the item — purely via the group grant.
        using (var scope = ScopeFor(provider, member, tenantId))
        {
            var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
            Assert.IsTrue((await vaults.ListSharedVaultsAsync(member, tenantId)).Any(v => v.Id == vaultId));
            Assert.AreEqual("group-secret", await vaults.ReadItemAsync(member, itemId));

            // Read-only: writing must be denied.
            await Assert.ThrowsExactlyAsync<UnauthorizedAccessException>(() =>
                vaults.AddItemAsync(new AddVaultItemCommand(member, vaultId, null, ItemType.SecureNote, "X", "x")));
        }

        // A tenant member OUTSIDE the group sees nothing.
        using (var scope = ScopeFor(provider, outsider, tenantId))
        {
            var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
            Assert.IsFalse((await vaults.ListSharedVaultsAsync(outsider, tenantId)).Any(v => v.Id == vaultId));
        }

        // Revoking the group's grant takes the member's access away.
        using (var scope = ScopeFor(provider, admin, tenantId))
        {
            var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
            await vaults.RevokeShareAsync(admin, tenantId, vaultId, PrincipalType.Group, groupId);
        }

        using (var scope = ScopeFor(provider, member, tenantId))
        {
            var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
            Assert.IsFalse((await vaults.ListSharedVaultsAsync(member, tenantId)).Any(v => v.Id == vaultId));
        }
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Group_lifecycle_is_restricted_to_tenant_admins()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var tenantId = Guid.NewGuid();
        var admin = Guid.NewGuid();
        var member = Guid.NewGuid();
        await SeedTenantAsync(provider, tenantId, (admin, TenantRole.TenantAdmin), (member, TenantRole.Member));

        using (var scope = ScopeFor(provider, member, tenantId))
        {
            var groups = scope.ServiceProvider.GetRequiredService<IGroupService>();
            Assert.IsFalse(await groups.CanManageGroupsAsync(member, tenantId));
            await Assert.ThrowsExactlyAsync<UnauthorizedAccessException>(() =>
                groups.CreateGroupAsync(member, tenantId, "Nope"));
        }

        Guid groupId;
        using (var scope = ScopeFor(provider, admin, tenantId))
        {
            var groups = scope.ServiceProvider.GetRequiredService<IGroupService>();
            groupId = await groups.CreateGroupAsync(admin, tenantId, "Ops");
            // A group ADMIN (not tenant admin) may manage members.
            await groups.AddMemberAsync(admin, tenantId, groupId, member, GroupRole.Admin);
        }

        using (var scope = ScopeFor(provider, member, tenantId))
        {
            var groups = scope.ServiceProvider.GetRequiredService<IGroupService>();
            await groups.SetMemberRoleAsync(member, tenantId, groupId, member, GroupRole.Member);
            // ... but having demoted themselves, member management is denied again.
            await Assert.ThrowsExactlyAsync<UnauthorizedAccessException>(() =>
                groups.RemoveMemberAsync(member, tenantId, groupId, member));
        }

        // Deleting the group removes its memberships.
        using (var scope = ScopeFor(provider, admin, tenantId))
        {
            var groups = scope.ServiceProvider.GetRequiredService<IGroupService>();
            await groups.DeleteGroupAsync(admin, tenantId, groupId);
            Assert.IsEmpty(await groups.ListGroupsAsync(admin, tenantId));
        }
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Team_vault_export_requires_the_tenant_admin_role()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var tenantId = Guid.NewGuid();
        var admin = Guid.NewGuid();
        var manager = Guid.NewGuid(); // holds a Manage grant — still NOT allowed to export
        await SeedTenantAsync(provider, tenantId, (admin, TenantRole.TenantAdmin), (manager, TenantRole.Member));

        Guid vaultId;
        using (var scope = ScopeFor(provider, admin, tenantId))
        {
            var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
            vaultId = await vaults.CreateTenantVaultAsync(new CreateTenantVaultCommand(admin, tenantId, "TeamVault"));
            await vaults.AddItemAsync(new AddVaultItemCommand(admin, vaultId, null, ItemType.Login, "Svc",
                LoginContent.ToJson("https://svc", "svc-user", "svc-pass", "")));
            await vaults.ShareWithUserAsync(new ShareVaultWithUserCommand(admin, tenantId, vaultId, manager, Permission.Manage));
        }

        using (var scope = ScopeFor(provider, manager, tenantId))
        {
            var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
            await Assert.ThrowsExactlyAsync<UnauthorizedAccessException>(() =>
                vaults.ExportVaultLoginsAsync(manager, vaultId));
        }

        using (var scope = ScopeFor(provider, admin, tenantId))
        {
            var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
            var exported = await vaults.ExportVaultLoginsAsync(admin, vaultId);
            Assert.AreEqual("svc-pass", exported.Single().Password);
        }
    }

    private static async Task SeedTenantAsync(ServiceProvider provider, Guid tenantId, params (Guid UserId, TenantRole Role)[] users)
    {
        using var scope = provider.CreateScope();
        scope.ServiceProvider.GetRequiredService<ITenantScopeSetter>().SetTenant(tenantId);
        var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
        db.Tenants.Add(new Tenant(tenantId, "groups-test", isSystemTenant: false, DateTimeOffset.UtcNow));
        foreach (var (userId, role) in users)
        {
            db.Users.Add(new AppUser(userId, issuer: null, externalId: userId.ToString(), displayName: $"user-{userId:N}", isSystemAdmin: false, DateTimeOffset.UtcNow));
            db.TenantMemberships.Add(new TenantMembership(Guid.NewGuid(), tenantId, userId, role, DateTimeOffset.UtcNow));
        }
        await db.SaveChangesAsync();
    }

    private static ServiceProvider BuildProvider()
    {
        var services = new ServiceCollection();
        services.AddKeyward(ConnectionString, RandomNumberGenerator.GetBytes(32), "test-kek:v1");
        return services.BuildServiceProvider();
    }

    private static async Task<bool> CanConnectAsync(ServiceProvider provider)
    {
        using var scope = provider.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<KeywardDbContext>().Database.CanConnectAsync();
    }

    private static IServiceScope ScopeFor(ServiceProvider provider, Guid userId, Guid tenantId)
    {
        var scope = provider.CreateScope();
        scope.ServiceProvider.GetRequiredService<IUserScopeSetter>().SetUser(userId);
        scope.ServiceProvider.GetRequiredService<ITenantScopeSetter>().SetTenant(tenantId);
        return scope;
    }
}
