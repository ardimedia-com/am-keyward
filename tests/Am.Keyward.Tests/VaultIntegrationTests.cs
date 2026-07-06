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
    private static readonly string ConnectionString = TestConfig.ConnectionString;

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

    [TestMethod, TestCategory("Integration")]
    public async Task Item_crud_and_login_import_round_trip()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var userId = Guid.NewGuid();
        Guid vaultId, itemId;
        using (var scope = ScopeForUser(provider, userId))
        {
            var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
            vaultId = await vaults.CreatePersonalVaultAsync(new CreatePersonalVaultCommand(userId, "Logins"));
            itemId = await vaults.AddItemAsync(new AddVaultItemCommand(
                userId, vaultId, null, ItemType.Login, "GitHub", LoginContent.ToJson("https://github.com", "octocat", "p@ss", "personal")));
        }

        using (var scope = ScopeForUser(provider, userId))
        {
            var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();

            var detail = await vaults.GetItemAsync(userId, itemId);
            Assert.IsNotNull(detail);
            var fields = LoginContent.Parse(detail.Content);
            Assert.AreEqual("octocat", fields.Username);
            Assert.AreEqual("p@ss", fields.Password);

            // Edit -> new version.
            await vaults.UpdateItemAsync(new UpdateVaultItemCommand(
                userId, itemId, "GitHub (work)", null, LoginContent.ToJson("https://github.com", "octocat", "rotated", "work")));
            var updated = await vaults.GetItemAsync(userId, itemId);
            Assert.AreEqual("GitHub (work)", updated!.Name);
            Assert.AreEqual("rotated", LoginContent.Parse(updated.Content).Password);

            // Import (e.g. an Edge export).
            var count = await vaults.ImportLoginsAsync(userId, vaultId,
            [
                new ImportedLogin("Site A", "https://a.example", "ua", "pa", ""),
                new ImportedLogin("Site B", "https://b.example", "ub", "pb", ""),
            ]);
            Assert.AreEqual(2, count);
            Assert.HasCount(3, await vaults.ListItemsAsync(userId, vaultId));

            // Delete.
            await vaults.DeleteItemAsync(userId, itemId);
            Assert.HasCount(2, await vaults.ListItemsAsync(userId, vaultId));
        }
    }

    [TestMethod, TestCategory("Integration")]
    public async Task A_reused_circuit_scoped_context_does_not_serve_stale_reads_after_an_update()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var userId = Guid.NewGuid();
        Guid itemId;
        using (var scope = ScopeForUser(provider, userId))
        {
            var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
            var vaultId = await vaults.CreatePersonalVaultAsync(new CreatePersonalVaultCommand(userId, "V"));
            itemId = await vaults.AddItemAsync(new AddVaultItemCommand(userId, vaultId, null, ItemType.SecureNote, "Note", "v1"));
        }

        // A long-lived (Blazor-circuit-like) scope reads the item — which tracks it — then another scope updates it.
        using var circuit = ScopeForUser(provider, userId);
        var circuitVaults = circuit.ServiceProvider.GetRequiredService<IVaultService>();
        Assert.AreEqual("v1", (await circuitVaults.GetItemAsync(userId, itemId))!.Content);

        using (var other = ScopeForUser(provider, userId))
        {
            await other.ServiceProvider.GetRequiredService<IVaultService>()
                .UpdateItemAsync(new UpdateVaultItemCommand(userId, itemId, "Note", null, "v2"));
        }

        // Re-reading through the SAME long-lived context must return the fresh value, not the stale tracked one
        // (the change-tracker reset after each save keeps the circuit-scoped context from serving stale reads).
        Assert.AreEqual("v2", (await circuitVaults.GetItemAsync(userId, itemId))!.Content);
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
