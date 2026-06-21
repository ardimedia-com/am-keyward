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
/// Personal-vault end-to-end (v0.1): create vault/folder/item, encrypt + read, and per-user isolation
/// (a user cannot reach another user's personal vault). Runs against a real SQL Server; skips when none.
/// </summary>
[TestClass]
public class VaultIntegrationTests
{
    private const string ConnectionString = "Server=localhost;Database=amkeyward;Integrated Security=True;Encrypt=False";

    [TestMethod, TestCategory("Integration")]
    public async Task Create_read_personal_vault_roundtrips_and_is_encrypted_at_rest()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var userId = Guid.NewGuid();
        const string secret = "username=admin;password=vault-super-secret";

        Guid vaultId, itemId;
        using (var scope = ScopeForUser(provider, userId))
        {
            var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
            vaultId = await vaults.CreatePersonalVaultAsync(new CreatePersonalVaultCommand(userId, "My Vault"));
            await vaults.AddFolderAsync(new AddVaultFolderCommand(userId, vaultId, "Logins"));
            itemId = await vaults.AddItemAsync(new AddVaultItemCommand(userId, vaultId, null, ItemType.Login, "GitHub", secret));
        }

        using (var scope = ScopeForUser(provider, userId))
        {
            var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
            Assert.AreEqual(secret, await vaults.ReadItemAsync(userId, itemId));

            var list = await vaults.ListVaultsAsync(userId);
            Assert.IsTrue(list.Any(v => v.Id == vaultId));
            Assert.HasCount(1, await vaults.ListFoldersAsync(userId, vaultId));
            Assert.HasCount(1, await vaults.ListItemsAsync(userId, vaultId));
        }

        using (var scope = ScopeForUser(provider, userId))
        {
            var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
            var stored = await db.Database
                .SqlQueryRaw<string>("SELECT [Encrypted] AS [Value] FROM [amkeyward].[VaultItemVersions]")
                .ToListAsync();
            Assert.IsNotEmpty(stored);
            Assert.IsFalse(stored.Any(c => c.Contains("vault-super-secret", StringComparison.Ordinal)),
                "Vault item plaintext must never be stored at rest.");
        }
    }

    [TestMethod, TestCategory("Integration")]
    public async Task A_user_cannot_reach_another_users_personal_vault()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var userA = Guid.NewGuid();
        var userB = Guid.NewGuid();

        Guid itemA;
        using (var scope = ScopeForUser(provider, userA))
        {
            var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
            var vaultA = await vaults.CreatePersonalVaultAsync(new CreatePersonalVaultCommand(userA, "A Vault"));
            itemA = await vaults.AddItemAsync(new AddVaultItemCommand(userA, vaultA, null, ItemType.SecureNote, "A note", "tenant-a-only"));
        }

        using var scopeB = ScopeForUser(provider, userB);
        var vaultsB = scopeB.ServiceProvider.GetRequiredService<IVaultService>();

        // Acting as B, A's item is invisible (query filter + RLS by user) -> not found.
        Assert.IsNull(await vaultsB.ReadItemAsync(userB, itemA));

        // Claiming to be A while signed in as B is rejected by the server-authoritative user check.
        await Assert.ThrowsExactlyAsync<UnauthorizedAccessException>(() => vaultsB.ReadItemAsync(userA, itemA));

        // B sees none of A's vaults.
        Assert.IsEmpty(await vaultsB.ListVaultsAsync(userB));
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

    private static IServiceScope ScopeForUser(ServiceProvider provider, Guid userId)
    {
        var scope = provider.CreateScope();
        scope.ServiceProvider.GetRequiredService<IUserScopeSetter>().SetUser(userId);
        return scope;
    }
}
