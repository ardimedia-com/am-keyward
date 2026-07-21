using System.Security.Cryptography;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Infrastructure;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Am.Keyward.Tests;

/// <summary>
/// Tenant ("team") vaults shared via grants: the creator has Manage, a grantee gets exactly the granted
/// permission, a non-grantee is denied, and another tenant cannot see the vault at all.
/// </summary>
[TestClass]
public class VaultSharingTests
{
    private static readonly string ConnectionString = TestConfig.ConnectionString;

    [TestMethod, TestCategory("Integration")]
    public async Task Tenant_vault_is_accessible_only_through_grants()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var tenantId = Guid.NewGuid();
        var creator = Guid.NewGuid();
        var grantee = Guid.NewGuid();
        var outsider = Guid.NewGuid();

        // creator and grantee are members of the tenant; the outsider is not. Team-vault access requires
        // tenant membership, so the participants must actually be members.
        using (var seed = ScopeFor(provider, tenantId, creator))
        {
            var db = seed.ServiceProvider.GetRequiredService<KeywardDbContext>();
            db.Tenants.Add(new Am.Keyward.Core.Domain.Identity.Tenant(tenantId, "system", isSystemTenant: true, DateTimeOffset.UtcNow));
            db.TenantMemberships.Add(new Am.Keyward.Core.Domain.Identity.TenantMembership(Guid.NewGuid(), tenantId, creator, TenantRole.Member, DateTimeOffset.UtcNow));
            db.TenantMemberships.Add(new Am.Keyward.Core.Domain.Identity.TenantMembership(Guid.NewGuid(), tenantId, grantee, TenantRole.Member, DateTimeOffset.UtcNow));
            await db.SaveChangesAsync();
        }

        Guid vaultId, itemId;
        using (var scope = ScopeFor(provider, tenantId, creator))
        {
            var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
            vaultId = await vaults.CreateTenantVaultAsync(new CreateTenantVaultCommand(creator, tenantId, "Team Vault"));
            itemId = await vaults.AddItemAsync(new AddVaultItemCommand(creator, vaultId, null, ItemType.Login, "Shared login", "team-secret"));
            Assert.AreEqual("team-secret", await vaults.ReadItemAsync(creator, itemId));
        }

        // Before sharing: the grantee is in the tenant but has no grant -> denied; sees no shared vaults.
        using (var scope = ScopeFor(provider, tenantId, grantee))
        {
            var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
            await Assert.ThrowsExactlyAsync<UnauthorizedAccessException>(() => vaults.ReadItemAsync(grantee, itemId));
            Assert.IsEmpty(await vaults.ListSharedVaultsAsync(grantee, tenantId));
        }

        // Creator (Manage) shares Read with the grantee.
        using (var scope = ScopeFor(provider, tenantId, creator))
        {
            await scope.ServiceProvider.GetRequiredService<IVaultService>()
                .ShareWithUserAsync(new ShareVaultWithUserCommand(creator, tenantId, vaultId, grantee, Permission.Read));
        }

        // Grantee can now read, sees the shared vault, but cannot write (only Read was granted).
        using (var scope = ScopeFor(provider, tenantId, grantee))
        {
            var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
            Assert.AreEqual("team-secret", await vaults.ReadItemAsync(grantee, itemId));
            Assert.IsTrue((await vaults.ListSharedVaultsAsync(grantee, tenantId)).Any(v => v.Id == vaultId));
            await Assert.ThrowsExactlyAsync<UnauthorizedAccessException>(() =>
                vaults.AddItemAsync(new AddVaultItemCommand(grantee, vaultId, null, ItemType.Generic, "x", "y")));
        }

        // A user with no grant is denied.
        using (var scope = ScopeFor(provider, tenantId, outsider))
        {
            await Assert.ThrowsExactlyAsync<UnauthorizedAccessException>(() =>
                scope.ServiceProvider.GetRequiredService<IVaultService>().ReadItemAsync(outsider, itemId));
        }

        // Another tenant cannot even see the vault or its item (isolation boundary).
        using (var scope = ScopeFor(provider, Guid.NewGuid(), outsider))
        {
            var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
            Assert.IsNull(await vaults.ReadItemAsync(outsider, itemId));
            Assert.IsEmpty(await vaults.ListSharedVaultsAsync(outsider, scope.ServiceProvider.GetRequiredService<ICurrentTenant>().TenantId!.Value));
        }
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

    private static IServiceScope ScopeFor(ServiceProvider provider, Guid tenantId, Guid userId)
    {
        var scope = provider.CreateScope();
        scope.ServiceProvider.GetRequiredService<ITenantScopeSetter>().SetTenant(tenantId);
        scope.ServiceProvider.GetRequiredService<IUserScopeSetter>().SetUser(userId);
        return scope;
    }
}
