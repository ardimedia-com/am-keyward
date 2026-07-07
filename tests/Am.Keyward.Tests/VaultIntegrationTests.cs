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

    [TestMethod, TestCategory("Integration")]
    public async Task Folders_form_a_tree_and_deleting_one_reparents_children_and_items()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var userId = Guid.NewGuid();
        using var scope = ScopeForUser(provider, userId);
        var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();

        var vaultId = await vaults.CreatePersonalVaultAsync(new CreatePersonalVaultCommand(userId, "Tree"));
        var parent = await vaults.AddFolderAsync(new AddVaultFolderCommand(userId, vaultId, "Parent"));
        var child = await vaults.AddFolderAsync(new AddVaultFolderCommand(userId, vaultId, "Child", parent));
        var grandchild = await vaults.AddFolderAsync(new AddVaultFolderCommand(userId, vaultId, "Grandchild", child));
        var itemInChild = await vaults.AddItemAsync(new AddVaultItemCommand(userId, vaultId, child, ItemType.SecureNote, "Note", "in child"));

        var folders = await vaults.ListFoldersAsync(userId, vaultId);
        Assert.AreEqual(parent, folders.Single(f => f.Id == child).ParentFolderId);
        Assert.AreEqual(child, folders.Single(f => f.Id == grandchild).ParentFolderId);

        // A parent from another vault is refused (tree stays within one vault).
        var otherVault = await vaults.CreatePersonalVaultAsync(new CreatePersonalVaultCommand(userId, "Other"));
        await Assert.ThrowsExactlyAsync<InvalidOperationException>(() =>
            vaults.AddFolderAsync(new AddVaultFolderCommand(userId, otherVault, "X", parent)));

        // Deleting the middle folder moves its child folder AND its item up to the deleted folder's parent.
        await vaults.DeleteFolderAsync(userId, vaultId, child);
        folders = await vaults.ListFoldersAsync(userId, vaultId);
        Assert.AreEqual(parent, folders.Single(f => f.Id == grandchild).ParentFolderId);
        var items = await vaults.ListItemsAsync(userId, vaultId);
        Assert.AreEqual(parent, items.Single(i => i.Id == itemInChild).FolderId);
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Move_changes_folder_within_a_vault_and_reencrypts_across_vaults()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var userId = Guid.NewGuid();
        using var scope = ScopeForUser(provider, userId);
        var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();

        var source = await vaults.CreatePersonalVaultAsync(new CreatePersonalVaultCommand(userId, "Source"));
        var target = await vaults.CreatePersonalVaultAsync(new CreatePersonalVaultCommand(userId, "Target"));
        var folder = await vaults.AddFolderAsync(new AddVaultFolderCommand(userId, source, "Inbox"));
        var targetFolder = await vaults.AddFolderAsync(new AddVaultFolderCommand(userId, target, "Archive"));
        var itemId = await vaults.AddItemAsync(new AddVaultItemCommand(userId, source, null, ItemType.SecureNote, "Note", "move-me-secret"));

        // Within the vault: just a folder change, same item id.
        var movedId = await vaults.MoveItemAsync(userId, itemId, source, folder);
        Assert.AreEqual(itemId, movedId);
        Assert.AreEqual(folder, (await vaults.ListItemsAsync(userId, source)).Single().FolderId);

        // Across vaults: new id in the target (re-encrypted there), gone from the source, content intact.
        movedId = await vaults.MoveItemAsync(userId, itemId, target, targetFolder);
        Assert.AreNotEqual(itemId, movedId);
        Assert.IsEmpty(await vaults.ListItemsAsync(userId, source));
        var moved = (await vaults.ListItemsAsync(userId, target)).Single();
        Assert.AreEqual(targetFolder, moved.FolderId);
        Assert.AreEqual("move-me-secret", await vaults.ReadItemAsync(userId, movedId));

        // A folder that belongs to a DIFFERENT vault than the target is refused.
        await Assert.ThrowsExactlyAsync<InvalidOperationException>(() =>
            vaults.MoveItemAsync(userId, movedId, source, targetFolder));

        // Batch move: several items travel together (atomically, one SaveChanges).
        var a = await vaults.AddItemAsync(new AddVaultItemCommand(userId, source, null, ItemType.SecureNote, "A", "a"));
        var b = await vaults.AddItemAsync(new AddVaultItemCommand(userId, source, null, ItemType.SecureNote, "B", "b"));
        await vaults.MoveItemsAsync(userId, [a, b], target, null);
        Assert.IsEmpty(await vaults.ListItemsAsync(userId, source));
        Assert.HasCount(3, await vaults.ListItemsAsync(userId, target));
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Folder_move_reparents_within_a_vault_and_takes_the_subtree_across_vaults()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var userId = Guid.NewGuid();
        using var scope = ScopeForUser(provider, userId);
        var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();

        var source = await vaults.CreatePersonalVaultAsync(new CreatePersonalVaultCommand(userId, "Source"));
        var target = await vaults.CreatePersonalVaultAsync(new CreatePersonalVaultCommand(userId, "Target"));
        var top = await vaults.AddFolderAsync(new AddVaultFolderCommand(userId, source, "Top"));
        var mid = await vaults.AddFolderAsync(new AddVaultFolderCommand(userId, source, "Mid", top));
        var leaf = await vaults.AddFolderAsync(new AddVaultFolderCommand(userId, source, "Leaf", mid));
        await vaults.AddItemAsync(new AddVaultItemCommand(userId, source, mid, ItemType.SecureNote, "InMid", "subtree-secret"));

        // Reparent within the vault: Mid moves to the root.
        Assert.AreEqual(mid, await vaults.MoveFolderAsync(userId, mid, source, null));
        Assert.IsNull((await vaults.ListFoldersAsync(userId, source)).Single(f => f.Id == mid).ParentFolderId);

        // Cycle guard: Top cannot move under its own descendant chain (Mid was under Top; move Top under Leaf after re-nesting Mid).
        await vaults.MoveFolderAsync(userId, mid, source, top);
        await Assert.ThrowsExactlyAsync<InvalidOperationException>(() =>
            vaults.MoveFolderAsync(userId, top, source, leaf));

        // Across vaults: the subtree (Top > Mid > Leaf) and the item inside move together, content intact.
        var movedTop = await vaults.MoveFolderAsync(userId, top, target, null);
        Assert.IsEmpty(await vaults.ListFoldersAsync(userId, source));
        Assert.IsEmpty(await vaults.ListItemsAsync(userId, source));
        var targetFolders = await vaults.ListFoldersAsync(userId, target);
        Assert.HasCount(3, targetFolders);
        var movedMid = targetFolders.Single(f => f.Name == "Mid");
        Assert.AreEqual(movedTop, movedMid.ParentFolderId);
        Assert.AreEqual(movedMid.Id, targetFolders.Single(f => f.Name == "Leaf").ParentFolderId);
        var movedItem = (await vaults.ListItemsAsync(userId, target)).Single();
        Assert.AreEqual(movedMid.Id, movedItem.FolderId);
        Assert.AreEqual("subtree-secret", await vaults.ReadItemAsync(userId, movedItem.Id));
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Export_roundtrips_logins_through_the_edge_csv()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var userId = Guid.NewGuid();
        using var scope = ScopeForUser(provider, userId);
        var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();

        var vaultId = await vaults.CreatePersonalVaultAsync(new CreatePersonalVaultCommand(userId, "Exportable"));
        await vaults.AddItemAsync(new AddVaultItemCommand(userId, vaultId, null, ItemType.Login, "GitHub",
            LoginContent.ToJson("https://github.com", "octo@example.com", "p4ss,with\"quote", "note, with comma")));
        await vaults.AddItemAsync(new AddVaultItemCommand(userId, vaultId, null, ItemType.Login, "Router",
            LoginContent.ToJson("http://192.168.1.1", "admin", "simple", "")));
        // Not part of the login CSV format:
        await vaults.AddItemAsync(new AddVaultItemCommand(userId, vaultId, null, ItemType.SecureNote, "Note", "keep me"));

        var exported = await vaults.ExportVaultLoginsAsync(userId, vaultId);
        Assert.HasCount(2, exported);

        // The CSV survives a full write -> parse round trip, including escaping — so a file exported here
        // can be re-imported unchanged.
        var reparsed = EdgePasswordCsv.Parse(EdgePasswordCsv.Write(exported));
        CollectionAssert.AreEqual(exported.ToList(), reparsed.ToList());
        Assert.AreEqual("p4ss,with\"quote", reparsed.Single(l => l.Name == "GitHub").Password);
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Search_finds_items_by_any_content_field_but_never_by_password()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var userId = Guid.NewGuid();
        using var scope = ScopeForUser(provider, userId);
        var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();

        // Two vaults, so the search demonstrably spans ALL of the user's vaults.
        var vault1 = await vaults.CreatePersonalVaultAsync(new CreatePersonalVaultCommand(userId, "First"));
        var vault2 = await vaults.CreatePersonalVaultAsync(new CreatePersonalVaultCommand(userId, "Second"));
        await vaults.AddItemAsync(new AddVaultItemCommand(userId, vault1, null, ItemType.Login, "GitHub",
            LoginContent.ToJson("https://github.com", "octo-user@example.com", "hunter2-password", "work account")));
        await vaults.AddItemAsync(new AddVaultItemCommand(userId, vault2, null, ItemType.SecureNote, "Wifi",
            "the office wifi key is stored here"));

        // Matches by login username (field content, not the item name) …
        var byUsername = await vaults.SearchItemsAsync(userId, Guid.NewGuid(), teamVaults: false, "octo-user");
        Assert.HasCount(1, byUsername);
        Assert.AreEqual("Username", byUsername[0].MatchedField);
        Assert.AreEqual("First", byUsername[0].VaultName);

        // … by a secure note's value in the OTHER vault …
        var byValue = await vaults.SearchItemsAsync(userId, Guid.NewGuid(), teamVaults: false, "office wifi");
        Assert.HasCount(1, byValue);
        Assert.AreEqual("Value", byValue[0].MatchedField);
        Assert.AreEqual("Second", byValue[0].VaultName);

        // … by item name; and NEVER by a login's password.
        Assert.HasCount(1, await vaults.SearchItemsAsync(userId, Guid.NewGuid(), teamVaults: false, "github"));
        Assert.IsEmpty(await vaults.SearchItemsAsync(userId, Guid.NewGuid(), teamVaults: false, "hunter2-password"));

        // Too-short queries return nothing instead of everything.
        Assert.IsEmpty(await vaults.SearchItemsAsync(userId, Guid.NewGuid(), teamVaults: false, "o"));
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
