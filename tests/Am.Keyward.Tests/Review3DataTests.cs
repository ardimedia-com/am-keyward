using System.Security.Cryptography;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Access;
using Am.Keyward.Core.Domain.Agent;
using Am.Keyward.Core.Domain.Audit;
using Am.Keyward.Core.Domain.Identity;
using Am.Keyward.Core.Domain.Software;
using Am.Keyward.Core.Domain.ValueObjects;
using Am.Keyward.Infrastructure;
using Am.Keyward.Infrastructure.Monitoring;
using Am.Keyward.Infrastructure.Persistence;
using Am.Keyward.Infrastructure.Statistics;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Am.Keyward.Tests;

/// <summary>
/// Code review 3, area «vaults, persistence, schema, background jobs»: notices marked once across groups, reveal
/// requests that cannot be socially engineered or flood the person, revisions that move on every change, history
/// that survives a move, audited agent enumeration, no duplicate grants or pseudonyms, folder deletion without
/// dangling references, heartbeats without statistics, retention and the single-instance lease.
/// </summary>
[TestClass]
public class Review3DataTests
{
    private static readonly string ConnectionString = TestConfig.ConnectionString;

    // --- M11: notices are marked once, for every group ---

    [TestMethod, TestCategory("Integration")]
    public async Task Alert_notices_of_both_categories_are_marked_once()
    {
        var presenter = new CapturingPresenter();
        await using var provider = BuildProvider(s => s.AddScoped<IKeywardAlertPresenter>(_ => presenter));
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var tenantId = Guid.NewGuid();
        var admin = Guid.NewGuid();
        await SeedTenantAsync(provider, tenantId, (admin, TenantRole.TenantAdmin));
        var tokenId = await SeedSoftwareClientTokenAsync(provider, tenantId);

        // One alert per category: the second category's mark was the one the change-tracker reset used to lose.
        var now = DateTimeOffset.UtcNow;
        Guid newIp, heartbeat;
        using (var scope = provider.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
            var first = new TokenAccessAlert(Guid.NewGuid(), tenantId, tokenId, TokenAccessAlertKind.NewIpAddress, "10.0.0.9", now);
            var second = new TokenAccessAlert(Guid.NewGuid(), tenantId, tokenId, TokenAccessAlertKind.HeartbeatMissed, null, now);
            db.TokenAccessAlerts.AddRange(first, second);
            await db.SaveChangesAsync();
            (newIp, heartbeat) = (first.Id, second.Id);
        }

        var job = new TokenAccessAlertNotificationService(
            provider.GetRequiredService<IServiceScopeFactory>(), provider.GetRequiredService<IClock>(),
            NullLogger<TokenAccessAlertNotificationService>.Instance);

        await job.NotifyFreshAlertsAsync(CancellationToken.None);
        Assert.AreEqual(2, presenter.TokenAlertCalls.Count(c => c == tenantId), "one delivery per category");

        using (var scope = provider.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
            var marked = await db.TokenAccessAlerts.AsNoTracking().Where(a => a.Id == newIp || a.Id == heartbeat).ToListAsync();
            Assert.IsTrue(marked.All(a => a.EmailedAt is not null), "both categories must be marked delivered");
        }

        presenter.TokenAlertCalls.Clear();
        await job.NotifyFreshAlertsAsync(CancellationToken.None);
        Assert.AreEqual(0, presenter.TokenAlertCalls.Count(c => c == tenantId), "nothing is re-sent");
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Agent_token_expiry_notices_for_two_owners_are_both_marked_once()
    {
        var presenter = new CapturingPresenter();
        await using var provider = BuildProvider(s => s.AddScoped<IKeywardAlertPresenter>(_ => presenter));
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var tenantId = Guid.NewGuid();
        var first = Guid.NewGuid();
        var second = Guid.NewGuid();
        await SeedTenantAsync(provider, tenantId, (first, TenantRole.Member), (second, TenantRole.Member));
        foreach (var owner in new[] { first, second })
        {
            using var scope = ScopeFor(provider, tenantId, owner);
            var vault = await scope.ServiceProvider.GetRequiredService<IVaultService>().CreateTenantVaultAsync(new CreateTenantVaultCommand(owner, tenantId, "vault"));
            await scope.ServiceProvider.GetRequiredService<IVaultService>().SetAgentAccessAsync(owner, vault, allowed: true);
            await scope.ServiceProvider.GetRequiredService<IAgentTokenService>().IssueAsync(new IssueAgentTokenCommand(
                owner, tenantId, "agent", AgentScopes.VaultList, [vault], ExpiresAt: DateTimeOffset.UtcNow.AddDays(5)));
        }

        var job = new AgentTokenExpiryNotificationService(
            provider.GetRequiredService<IServiceScopeFactory>(), provider.GetRequiredService<IClock>(),
            Options.Create(new MonitoringOptions()), NullLogger<AgentTokenExpiryNotificationService>.Instance);

        await job.NotifyDueTokensAsync(CancellationToken.None);
        Assert.AreEqual(1, presenter.AgentExpiryRecipients.Count(r => r == first));
        Assert.AreEqual(1, presenter.AgentExpiryRecipients.Count(r => r == second));

        presenter.AgentExpiryRecipients.Clear();
        await job.NotifyDueTokensAsync(CancellationToken.None);
        Assert.IsFalse(presenter.AgentExpiryRecipients.Contains(first));
        Assert.IsFalse(presenter.AgentExpiryRecipients.Contains(second), "the second owner's mark must persist too");
    }

    // --- M9: reveal requests ---

    [TestMethod, TestCategory("Integration")]
    public async Task A_reveal_request_shows_the_name_before_an_agent_rename_and_is_voided_when_the_agent_changes_the_item()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var (tenantId, owner, _, tokenId, itemId) = await SeedAgentSetupAsync(provider, "Prod DB root");

        // The agent renames the entry to something harmless, then asks for the password.
        await AsAgentAsync(provider, tenantId, owner, tokenId, async (vaults, _) =>
        {
            var reference = await vaults.GetItemReferenceAsync(owner, itemId);
            await vaults.PatchItemAsync(new PatchVaultItemCommand(owner, itemId, reference!.VersionId, Name: "wifi guest"));
        });
        await AsAgentAsync(provider, tenantId, owner, tokenId, (_, reveals) =>
            reveals.RequestAsync(tokenId, itemId, RevealField.Password, "need it"));

        PendingRevealRequest pending;
        using (var scope = ScopeFor(provider, tenantId, owner))
        {
            pending = (await scope.ServiceProvider.GetRequiredService<IRevealRequestService>().ListPendingAsync(owner, tenantId)).Single();
        }

        Assert.AreEqual("wifi guest", pending.ItemName);
        Assert.AreEqual("Prod DB root", pending.ItemNameBeforeAgentRename, "the person must see what the entry was called");
        Assert.IsFalse(pending.ItemChangedSinceRequest);

        // Renaming it back voids the pending request: there is nothing left to approve.
        await AsAgentAsync(provider, tenantId, owner, tokenId, async (vaults, _) =>
        {
            var reference = await vaults.GetItemReferenceAsync(owner, itemId);
            await vaults.PatchItemAsync(new PatchVaultItemCommand(owner, itemId, reference!.VersionId, Name: "Prod DB root"));
        });

        using (var scope = ScopeFor(provider, tenantId, owner))
        {
            Assert.IsEmpty(await scope.ServiceProvider.GetRequiredService<IRevealRequestService>().ListPendingAsync(owner, tenantId));
            var stored = await scope.ServiceProvider.GetRequiredService<KeywardDbContext>().RevealRequests.AsNoTracking().SingleAsync(r => r.Id == pending.Id);
            Assert.AreEqual(RevealRequestStatus.Voided, stored.Status);
        }

        // A change by the person after a request is flagged, with the current name.
        await AsAgentAsync(provider, tenantId, owner, tokenId, (_, reveals) =>
            reveals.RequestAsync(tokenId, itemId, RevealField.Note, "the note"));
        using (var scope = ScopeFor(provider, tenantId, owner))
        {
            var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
            var reference = await vaults.GetItemReferenceAsync(owner, itemId);
            await vaults.PatchItemAsync(new PatchVaultItemCommand(owner, itemId, reference!.VersionId, Name: "Prod DB root (old)"));
        }

        using (var scope = ScopeFor(provider, tenantId, owner))
        {
            var changed = (await scope.ServiceProvider.GetRequiredService<IRevealRequestService>().ListPendingAsync(owner, tenantId)).Single();
            Assert.AreEqual("Prod DB root", changed.ItemName);
            Assert.IsNull(changed.ItemNameBeforeAgentRename, "a person's rename clears the agent marker");
            Assert.IsTrue(changed.ItemChangedSinceRequest);
            Assert.AreEqual("Prod DB root (old)", changed.CurrentItemName);
        }
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Reveal_requests_are_reused_per_item_and_field_and_capped_per_token()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var (tenantId, owner, vaultId, tokenId, itemId) = await SeedAgentSetupAsync(provider, "first");
        var more = new List<Guid>();
        using (var scope = ScopeFor(provider, tenantId, owner))
        {
            var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
            for (var i = 0; i < 3; i++)
            {
                more.Add(await vaults.AddItemAsync(new AddVaultItemCommand(owner, vaultId, null, ItemType.Generic, $"item {i}", "v")));
            }
        }

        RevealRequestState first = null!, again = null!;
        await AsAgentAsync(provider, tenantId, owner, tokenId, async (_, reveals) =>
        {
            first = await reveals.RequestAsync(tokenId, itemId, RevealField.Password, "one");
            again = await reveals.RequestAsync(tokenId, itemId, RevealField.Password, "one more time");
            await reveals.RequestAsync(tokenId, more[0], RevealField.Value, "two");
            await reveals.RequestAsync(tokenId, more[1], RevealField.Value, "three");
            await Assert.ThrowsExactlyAsync<RevealRequestLimitExceededException>(() =>
                reveals.RequestAsync(tokenId, more[2], RevealField.Value, "four"));
        });

        Assert.AreEqual(first.Id, again.Id, "the open request is reused, not duplicated");
        using var check = ScopeFor(provider, tenantId, owner);
        Assert.HasCount(3, await check.ServiceProvider.GetRequiredService<IRevealRequestService>().ListPendingAsync(owner, tenantId));
    }

    // --- revision / ETag, version counter, moves ---

    [TestMethod, TestCategory("Integration")]
    public async Task A_rename_moves_the_revision_and_stale_updates_conflict()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var user = Guid.NewGuid();
        using var scope = ScopeFor(provider, tenantId: null, user);
        var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
        var vault = await vaults.CreatePersonalVaultAsync(new CreatePersonalVaultCommand(user, "mine"));
        var item = await vaults.AddItemAsync(new AddVaultItemCommand(user, vault, null, ItemType.Generic, "name", "value"));

        var r1 = (await vaults.GetItemReferenceAsync(user, item))!.VersionId;
        await vaults.UpdateItemAsync(new UpdateVaultItemCommand(user, item, "renamed", null, "value", r1));
        var r2 = (await vaults.GetItemReferenceAsync(user, item))!.VersionId;
        Assert.AreNotEqual(r1, r2);

        // The UI path now refuses a stale edit instead of overwriting it.
        await Assert.ThrowsExactlyAsync<VaultItemVersionConflictException>(() =>
            vaults.UpdateItemAsync(new UpdateVaultItemCommand(user, item, "lost update", null, "other", r1)));

        // A name-only patch writes no version but still moves the revision (the agent API's ETag).
        var patched = await vaults.PatchItemAsync(new PatchVaultItemCommand(user, item, r2, Name: "again"));
        Assert.AreNotEqual(r2, patched.VersionId);
        await Assert.ThrowsExactlyAsync<VaultItemVersionConflictException>(() =>
            vaults.PatchItemAsync(new PatchVaultItemCommand(user, item, r2, Name: "concurrent rename")));

        var detail = await vaults.GetItemAsync(user, item);
        Assert.AreEqual(patched.VersionId, detail!.VersionId);
        Assert.AreEqual("again", detail.Name);
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Version_numbers_continue_after_the_history_was_pruned()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var user = Guid.NewGuid();
        using var scope = ScopeFor(provider, tenantId: null, user);
        var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
        var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
        var vault = await vaults.CreatePersonalVaultAsync(new CreatePersonalVaultCommand(user, "mine"));
        var item = await vaults.AddItemAsync(new AddVaultItemCommand(user, vault, null, ItemType.Generic, "n", "v1"));
        await vaults.UpdateItemAsync(new UpdateVaultItemCommand(user, item, "n", null, "v2"));
        await vaults.UpdateItemAsync(new UpdateVaultItemCommand(user, item, "n", null, "v3"));

        await db.VaultItemVersions.Where(v => v.VaultItemId == item && v.VersionNumber < 3).ExecuteDeleteAsync();
        await vaults.UpdateItemAsync(new UpdateVaultItemCommand(user, item, "n", null, "v4"));

        var numbers = await db.VaultItemVersions.AsNoTracking().Where(v => v.VaultItemId == item).Select(v => v.VersionNumber).OrderBy(n => n).ToListAsync();
        CollectionAssert.AreEqual(new[] { 3, 4 }, numbers);
        Assert.AreEqual("v4", await vaults.ReadItemAsync(user, item));
    }

    [TestMethod, TestCategory("Integration")]
    public async Task A_cross_vault_move_carries_the_whole_history()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var user = Guid.NewGuid();
        using var scope = ScopeFor(provider, tenantId: null, user);
        var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
        var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
        var source = await vaults.CreatePersonalVaultAsync(new CreatePersonalVaultCommand(user, "source"));
        var target = await vaults.CreatePersonalVaultAsync(new CreatePersonalVaultCommand(user, "target"));
        var item = await vaults.AddItemAsync(new AddVaultItemCommand(user, source, null, ItemType.Generic, "history", "v1"));
        await vaults.UpdateItemAsync(new UpdateVaultItemCommand(user, item, "history", null, "v2"));
        await vaults.UpdateItemAsync(new UpdateVaultItemCommand(user, item, "history", null, "v3"));
        var publicId = (await vaults.GetItemReferenceAsync(user, item))!.PublicId;

        var moved = await vaults.MoveItemAsync(user, item, target, null);

        Assert.AreNotEqual(item, moved);
        var versions = await db.VaultItemVersions.AsNoTracking().Where(v => v.VaultItemId == moved).OrderBy(v => v.VersionNumber).ToListAsync();
        CollectionAssert.AreEqual(new[] { 1, 2, 3 }, versions.Select(v => v.VersionNumber).ToList());
        Assert.IsFalse(await db.VaultItemVersions.AsNoTracking().AnyAsync(v => v.VaultItemId == item));
        Assert.AreEqual("v3", await vaults.ReadItemAsync(user, moved));
        Assert.AreEqual(publicId, (await vaults.GetItemReferenceAsync(user, moved))!.PublicId);

        // Every carried version decrypts under the target's binding.
        var vault = await db.Vaults.AsNoTracking().SingleAsync(v => v.Id == target);
        var backend = scope.ServiceProvider.GetRequiredService<ISecretBackend>();
        var first = versions[0];
        var plaintext = await backend.UnprotectAsync(first.Encrypted, Aad.ForVaultItemVersion(vault.TenantId, vault.OwnerType, vault.OwnerId, moved, first.Id, 1));
        Assert.AreEqual("v1", System.Text.Encoding.UTF8.GetString(plaintext));
    }

    [TestMethod, TestCategory("Integration")]
    public async Task An_agent_cannot_move_a_team_entry_into_a_personal_vault_but_a_person_can()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var (tenantId, owner, _, tokenId, itemId) = await SeedAgentSetupAsync(provider, "team entry");
        Guid personal;
        using (var scope = ScopeFor(provider, tenantId, owner))
        {
            personal = await scope.ServiceProvider.GetRequiredService<IVaultService>().CreatePersonalVaultAsync(new CreatePersonalVaultCommand(owner, "mine"));
        }

        await AsAgentAsync(provider, tenantId, owner, tokenId, async (vaults, _) =>
            await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => vaults.MoveItemAsync(owner, itemId, personal, null)));

        using (var scope = ScopeFor(provider, tenantId, owner))
        {
            var moved = await scope.ServiceProvider.GetRequiredService<IVaultService>().MoveItemAsync(owner, itemId, personal, null);
            Assert.IsNotNull(await scope.ServiceProvider.GetRequiredService<IVaultService>().GetItemReferenceAsync(owner, moved));
        }
    }

    // --- M10: agent enumeration leaves a trail ---

    [TestMethod, TestCategory("Integration")]
    public async Task Agent_listing_and_search_are_audited_but_a_persons_are_not()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var (tenantId, owner, vaultId, tokenId, _) = await SeedAgentSetupAsync(provider, "searchable");

        using (var scope = ScopeFor(provider, tenantId, owner))
        {
            var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
            await vaults.ListItemsAsync(owner, vaultId);
            await vaults.ListFoldersAsync(owner, vaultId);
            await vaults.SearchItemNamesAsync(owner, [vaultId], "search");
        }

        Assert.AreEqual(0, await CountAuditAsync(provider, tenantId, owner, "VaultList", "VaultSearch"), "a person's browsing is not audited");

        await AsAgentAsync(provider, tenantId, owner, tokenId, async (vaults, _) =>
        {
            await vaults.ListItemsAsync(owner, vaultId);
            await vaults.ListFoldersAsync(owner, vaultId);
            var hits = await vaults.SearchItemNamesAsync(owner, [vaultId], "search");
            Assert.HasCount(1, hits);
        });

        Assert.AreEqual(2, await CountAuditAsync(provider, tenantId, owner, "VaultList"));
        Assert.AreEqual(1, await CountAuditAsync(provider, tenantId, owner, "VaultSearch"));
    }

    // --- no duplicate grants or pseudonyms ---

    [TestMethod, TestCategory("Integration")]
    public async Task Concurrent_shares_with_the_same_user_leave_exactly_one_grant()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var tenantId = Guid.NewGuid();
        var owner = Guid.NewGuid();
        var grantee = Guid.NewGuid();
        await SeedTenantAsync(provider, tenantId, (owner, TenantRole.Member), (grantee, TenantRole.Member));
        Guid vaultId;
        using (var scope = ScopeFor(provider, tenantId, owner))
        {
            vaultId = await scope.ServiceProvider.GetRequiredService<IVaultService>().CreateTenantVaultAsync(new CreateTenantVaultCommand(owner, tenantId, "shared"));
        }

        var permissions = new[] { Permission.Read, Permission.Write, Permission.Manage, Permission.Read, Permission.Write, Permission.Read };
        await Task.WhenAll(permissions.Select(async permission =>
        {
            using var scope = ScopeFor(provider, tenantId, owner);
            await scope.ServiceProvider.GetRequiredService<IVaultService>().ShareWithUserAsync(
                new ShareVaultWithUserCommand(owner, tenantId, vaultId, grantee, permission));
        }));

        using (var scope = ScopeFor(provider, tenantId, owner))
        {
            var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
            Assert.AreEqual(1, await db.AccessGrants.CountAsync(g => g.PrincipalId == grantee && g.Scope.TargetId == vaultId));

            // The index itself refuses a second row, whatever the service does.
            db.AccessGrants.Add(new AccessGrant(Guid.NewGuid(), tenantId, PrincipalType.User, grantee,
                new GrantScope(GrantScopeKind.Vault, vaultId), Permission.Read, owner, DateTimeOffset.UtcNow));
            var ex = await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
            Assert.IsTrue(ex.IsUniqueViolationOn(VaultService.AccessGrantUniqueIndex));
        }
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Concurrent_first_audits_of_a_new_actor_create_one_pseudonym()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var reference = Guid.NewGuid().ToString("D");
        var ids = await Task.WhenAll(Enumerable.Range(0, 8).Select(async _ =>
        {
            using var scope = provider.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
            return await scope.ServiceProvider.GetRequiredService<DbAuditSubjectDirectory>()
                .ResolvePseudonymAsync(db, reference, new AuditSubjectPii("racer", reference));
        }));

        Assert.HasCount(1, ids.Distinct());
        using var check = provider.CreateScope();
        Assert.AreEqual(1, await check.ServiceProvider.GetRequiredService<KeywardDbContext>().AuditSubjects
            .CountAsync(s => s.SubjectReference == reference && s.ErasedAt == null));
    }

    // --- M17: folder deletion never leaves a dangling reference ---

    [TestMethod, TestCategory("Integration")]
    public async Task Deleting_a_folder_while_items_are_added_into_it_leaves_no_dangling_folder_reference()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var user = Guid.NewGuid();
        Guid vault, folder;
        using (var scope = ScopeFor(provider, tenantId: null, user))
        {
            var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
            vault = await vaults.CreatePersonalVaultAsync(new CreatePersonalVaultCommand(user, "race"));
            folder = await vaults.AddFolderAsync(new AddVaultFolderCommand(user, vault, "doomed"));
        }

        var adds = Enumerable.Range(0, 8).Select(async i =>
        {
            using var scope = ScopeFor(provider, tenantId: null, user);
            try
            {
                await scope.ServiceProvider.GetRequiredService<IVaultService>().AddItemAsync(
                    new AddVaultItemCommand(user, vault, folder, ItemType.Generic, $"item {i}", "v"));
            }
            catch (InvalidOperationException)
            {
                // The folder was already gone — the correct refusal.
            }
        });
        var delete = Task.Run(async () =>
        {
            using var scope = ScopeFor(provider, tenantId: null, user);
            await scope.ServiceProvider.GetRequiredService<IVaultService>().DeleteFolderAsync(user, vault, folder);
        });
        await Task.WhenAll(adds.Append(delete));

        using var check = ScopeFor(provider, tenantId: null, user);
        var db = check.ServiceProvider.GetRequiredService<KeywardDbContext>();
        var folderIds = await db.Folders.Where(f => f.VaultId == vault).Select(f => f.Id).ToListAsync();
        var dangling = await db.VaultItems.Where(i => i.VaultId == vault && i.FolderId != null && !folderIds.Contains(i.FolderId.Value)).CountAsync();
        Assert.AreEqual(0, dangling);
        Assert.IsFalse(folderIds.Contains(folder));
    }

    // --- M16: heartbeats without statistics ---

    [TestMethod, TestCategory("Integration")]
    public async Task With_statistics_disabled_the_flush_still_records_last_access_and_agent_use_and_drains_everything()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var (tenantId, _, _, agentTokenId, _) = await SeedAgentSetupAsync(provider, "x");
        var clientTokenId = await SeedSoftwareClientTokenAsync(provider, tenantId);
        var clock = provider.GetRequiredService<IClock>();
        var monitoring = Options.Create(new MonitoringOptions());
        var accesses = new TokenAccessAccumulator(clock, monitoring);
        var secretReads = new SecretReadAccumulator(clock);
        var agentUses = new AgentTokenAccessAccumulator(clock);
        accesses.Record(clientTokenId, "10.1.2.3");
        secretReads.Record(tenantId, Guid.NewGuid(), Guid.NewGuid(), SecretReadSource.Client);
        agentUses.Record(agentTokenId, "10.4.5.6");

        var flush = new TokenAccessFlushService(
            accesses, secretReads, agentUses, provider.GetRequiredService<IServiceScopeFactory>(), clock,
            Options.Create(new TokenAccessOptions { Enabled = false }), monitoring, NullLogger<TokenAccessFlushService>.Instance);
        await flush.FlushAsync(statisticsEnabled: false, CancellationToken.None);

        using var scope = provider.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
        var client = await db.SoftwareClientTokens.AsNoTracking().SingleAsync(t => t.Id == clientTokenId);
        Assert.IsNotNull(client.LastAccessAt, "the heartbeat signal is written without statistics");
        Assert.AreEqual("10.1.2.3", client.LastAccessIp);
        Assert.IsFalse(await db.TokenDailyAccesses.AnyAsync(d => d.TokenId == clientTokenId), "no statistics rows");
        var agent = await db.AgentTokens.AsNoTracking().SingleAsync(t => t.Id == agentTokenId);
        Assert.IsNotNull(agent.LastUsedAt);
        Assert.AreEqual("10.4.5.6", agent.LastUsedIp);
        Assert.IsEmpty(secretReads.Drain(), "the secret-read accumulator was drained, not left to grow");

        using var summaryScope = ScopeFor(provider, tenantId, agent.UserId);
        var summary = (await summaryScope.ServiceProvider.GetRequiredService<IAgentTokenService>().ListAsync(agent.UserId, tenantId)).Single();
        Assert.AreEqual("10.4.5.6", summary.LastUsedIp);
    }

    [TestMethod, TestCategory("Unit")]
    public void The_allowed_silence_has_a_floor_of_check_plus_flush_interval()
    {
        Assert.AreEqual(3, HeartbeatTiming.MinimumMaxSilenceMinutes(new MonitoringOptions(), new TokenAccessOptions()));
        Assert.AreEqual(12, HeartbeatTiming.MinimumMaxSilenceMinutes(
            new MonitoringOptions { CheckIntervalSeconds = 300 }, new TokenAccessOptions { FlushIntervalSeconds = 360 }));
    }

    // --- retention ---

    [TestMethod, TestCategory("Integration")]
    public async Task Retention_removes_personal_vaults_of_accounts_deleted_long_ago_and_old_reveal_requests()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var (tenantId, owner, _, tokenId, itemId) = await SeedAgentSetupAsync(provider, "requested");
        var longGone = Guid.NewGuid();
        var recentlyGone = Guid.NewGuid();
        var vaultOf = new Dictionary<Guid, Guid>();
        foreach (var user in new[] { longGone, recentlyGone })
        {
            using (var seed = provider.CreateScope())
            {
                var db = seed.ServiceProvider.GetRequiredService<KeywardDbContext>();
                db.Users.Add(new AppUser(user, issuer: null, externalId: $"user-{user:N}", displayName: "leaver", isSystemAdmin: false, DateTimeOffset.UtcNow));
                await db.SaveChangesAsync();
            }

            using var scope = ScopeFor(provider, tenantId: null, user);
            var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
            vaultOf[user] = await vaults.CreatePersonalVaultAsync(new CreatePersonalVaultCommand(user, "personal"));
            await vaults.AddItemAsync(new AddVaultItemCommand(user, vaultOf[user], null, ItemType.Generic, "secret", "v"));
        }

        using (var scope = provider.CreateScope())
        {
            var deletion = scope.ServiceProvider.GetRequiredService<IKeywardAccountDeletion>();
            Assert.IsTrue(await deletion.DeleteAccountAsync($"user-{longGone:N}"));
            Assert.IsTrue(await deletion.DeleteAccountAsync($"user-{recentlyGone:N}"));
            Assert.IsFalse(await deletion.DeleteAccountAsync($"user-{Guid.NewGuid():N}"));

            // The retention clock of one of them started 91 days ago.
            var longAgo = DateTimeOffset.UtcNow.AddDays(-91);
            await scope.ServiceProvider.GetRequiredService<KeywardDbContext>().Users
                .Where(u => u.Id == longGone)
                .ExecuteUpdateAsync(s => s.SetProperty(u => u.DeletedAt, longAgo));
        }

        // One reveal request from 40 days ago (history), one current.
        Guid oldRequest;
        using (var scope = ScopeFor(provider, tenantId, owner))
        {
            var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
            var old = new RevealRequest(Guid.NewGuid(), tenantId, tokenId, owner, itemId, RevealField.Password, "old", DateTimeOffset.UtcNow.AddDays(-40), "requested", Guid.NewGuid());
            db.RevealRequests.Add(old);
            await db.SaveChangesAsync();
            oldRequest = old.Id;
        }

        await AsAgentAsync(provider, tenantId, owner, tokenId, (_, reveals) => reveals.RequestAsync(tokenId, itemId, RevealField.Password, "fresh"));

        var job = new KeywardRetentionBackgroundService(
            provider.GetRequiredService<IServiceScopeFactory>(), provider.GetRequiredService<IClock>(),
            Options.Create(new KeywardRetentionOptions()), NullLogger<KeywardRetentionBackgroundService>.Instance);
        await job.RunOnceAsync(CancellationToken.None);

        using (var scope = ScopeFor(provider, tenantId: null, longGone))
        {
            var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
            Assert.IsFalse(await db.Vaults.AnyAsync(v => v.Id == vaultOf[longGone]), "removed after the retention period");
            Assert.IsFalse(await db.VaultItems.AnyAsync(i => i.VaultId == vaultOf[longGone]));
        }

        using (var scope = ScopeFor(provider, tenantId: null, recentlyGone))
        {
            Assert.IsTrue(await scope.ServiceProvider.GetRequiredService<KeywardDbContext>().Vaults.AnyAsync(v => v.Id == vaultOf[recentlyGone]),
                "kept within the retention period");
        }

        using (var scope = ScopeFor(provider, tenantId, owner))
        {
            var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
            Assert.IsFalse(await db.RevealRequests.AnyAsync(r => r.Id == oldRequest));
            Assert.AreEqual(1, await db.RevealRequests.CountAsync(r => r.TokenId == tokenId));
        }
    }

    [TestMethod, TestCategory("Unit")]
    public void Enabling_a_deleted_user_cancels_the_deletion()
    {
        var user = new AppUser(Guid.NewGuid(), null, "x", "x", false, DateTimeOffset.UtcNow);
        var at = DateTimeOffset.UtcNow;
        user.MarkDeleted(at);
        Assert.IsTrue(user.IsDisabled);
        Assert.AreEqual(at, user.DeletedAt);
        user.MarkDeleted(at.AddDays(1));
        Assert.AreEqual(at, user.DeletedAt, "the retention clock starts at the first deletion");
        user.Enable();
        Assert.IsFalse(user.IsDeleted);
        Assert.IsFalse(user.IsDisabled);
    }

    // --- M15: one instance per database ---

    [TestMethod, TestCategory("Integration")]
    public async Task A_second_instance_cannot_take_the_single_instance_lease()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        // A private resource: other test hosts in this run hold the real one.
        var resource = $"Keyward_SingleInstance_test_{Guid.NewGuid():N}";
        var scopes = provider.GetRequiredService<IServiceScopeFactory>();
        var clock = provider.GetRequiredService<IClock>();
        var firstState = new KeywardInstanceLeaseState();
        var secondState = new KeywardInstanceLeaseState();
        using var first = new KeywardInstanceLease(scopes, firstState, clock, NullLogger<KeywardInstanceLease>.Instance) { Resource = resource };
        using var second = new KeywardInstanceLease(scopes, secondState, clock, NullLogger<KeywardInstanceLease>.Instance) { Resource = resource };

        Assert.AreEqual(KeywardInstanceLeaseStatus.Held, await first.CheckAsync(CancellationToken.None));
        Assert.AreEqual(KeywardInstanceLeaseStatus.HeldElsewhere, await second.CheckAsync(CancellationToken.None));
        Assert.AreEqual(KeywardInstanceLeaseStatus.Held, await first.CheckAsync(CancellationToken.None), "a held lease stays held");

        var health = await new KeywardSingleInstanceHealthCheck(secondState).CheckHealthAsync(new());
        Assert.AreEqual(Microsoft.Extensions.Diagnostics.HealthChecks.HealthStatus.Unhealthy, health.Status);

        first.Dispose(); // the process ends: its session — and the lock — go with it
        Assert.AreEqual(KeywardInstanceLeaseStatus.Held, await second.CheckAsync(CancellationToken.None));
    }

    // --- audit chain and retries ---

    [TestMethod, TestCategory("Integration")]
    public async Task A_sequence_collision_after_a_lost_chain_lock_fails_the_save_instead_of_forking_the_chain()
    {
        var tenantId = Guid.NewGuid();
        await using var normal = BuildProvider();
        if (!await CanConnectAsync(normal))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        // Simulates what a transient-error retry does: EF reconnects (the new session has no chain lock) after the
        // entry was sealed — and another writer appends in between, taking the same sequence number.
        var intruder = new LoseLockThenIntrude(tenantId, async () =>
        {
            using var scope = ScopeFor(normal, tenantId, userId: null);
            await scope.ServiceProvider.GetRequiredService<IAuditSink>().AppendAsync(new AuditRequest(tenantId, AuditAction.Read, "Intruder", null, null));
            await scope.ServiceProvider.GetRequiredService<KeywardDbContext>().SaveChangesAsync();
        });
        await using var racing = BuildProvider(s => s.ConfigureDbContext<KeywardDbContext>(o => o.AddInterceptors(intruder)));

        using (var scope = ScopeFor(normal, tenantId, userId: null))
        {
            await scope.ServiceProvider.GetRequiredService<IAuditSink>().AppendAsync(new AuditRequest(tenantId, AuditAction.Read, "First", null, null));
            await scope.ServiceProvider.GetRequiredService<KeywardDbContext>().SaveChangesAsync();
        }

        using (var scope = ScopeFor(racing, tenantId, userId: null))
        {
            await scope.ServiceProvider.GetRequiredService<IAuditSink>().AppendAsync(new AuditRequest(tenantId, AuditAction.Read, "Loser", null, null));
            var ex = await Assert.ThrowsAsync<DbUpdateException>(() => scope.ServiceProvider.GetRequiredService<KeywardDbContext>().SaveChangesAsync());
            Assert.IsInstanceOfType<SqlException>(ex.InnerException);
            Assert.IsTrue(((SqlException)ex.InnerException!).Number is 2601 or 2627, "a unique-key conflict the caller can retry");
        }

        // The retry (a fresh unit of work) appends after the intruder; the chain never forked.
        using (var scope = ScopeFor(normal, tenantId, userId: null))
        {
            await scope.ServiceProvider.GetRequiredService<IAuditSink>().AppendAsync(new AuditRequest(tenantId, AuditAction.Read, "Retry", null, null));
            await scope.ServiceProvider.GetRequiredService<KeywardDbContext>().SaveChangesAsync();
        }

        using (var scope = ScopeFor(normal, tenantId, userId: null))
        {
            var status = await scope.ServiceProvider.GetRequiredService<IAuditChainVerifier>().VerifyAsync(tenantId);
            Assert.IsTrue(status.IsIntact, status.Detail);
            Assert.AreEqual(3L, status.EntriesChecked);
            var types = await scope.ServiceProvider.GetRequiredService<KeywardDbContext>().AuditEntries
                .Where(e => e.TenantId == tenantId).OrderBy(e => e.Sequence).Select(e => e.ResourceType).ToListAsync();
            CollectionAssert.AreEqual(new[] { "First", "Intruder", "Retry" }, types);
        }
    }

    // --- helpers ---

    private sealed class LoseLockThenIntrude(Guid tenantId, Func<Task> intrude) : SaveChangesInterceptor
    {
        private int fired;

        public override async ValueTask<InterceptionResult<int>> SavingChangesAsync(
            DbContextEventData eventData, InterceptionResult<int> result, CancellationToken ct = default)
        {
            if (eventData.Context is { } context
                && context.ChangeTracker.Entries<AuditEntry>().Any(e => e.State == EntityState.Added)
                && Interlocked.Exchange(ref fired, 1) == 0)
            {
                await using (var release = context.Database.GetDbConnection().CreateCommand())
                {
                    release.CommandText = $"EXEC sp_releaseapplock @Resource = N'Keyward_AuditChain_{tenantId:N}', @LockOwner = 'Session';";
                    await release.ExecuteNonQueryAsync(ct);
                }

                await intrude();
            }

            return result;
        }
    }

    private sealed class CapturingPresenter : IKeywardAlertPresenter
    {
        public List<Guid> TokenAlertCalls { get; } = [];

        public List<Guid> AgentExpiryRecipients { get; } = [];

        public bool OwnsRecipientSelection => false;

        public Task<int> NotifyTokenAlertsAsync(Guid tenantId, bool monitoring, IReadOnlyList<KeywardAlertRecipient> recipients, IReadOnlyList<KeywardTokenAlertLine> lines, CancellationToken ct = default)
        {
            lock (TokenAlertCalls)
            {
                TokenAlertCalls.Add(tenantId);
            }

            return Task.FromResult(recipients.Count);
        }

        public Task<int> NotifyTokenExpiryAsync(Guid tenantId, IReadOnlyList<KeywardAlertRecipient> recipients, IReadOnlyList<KeywardTokenExpiryLine> lines, CancellationToken ct = default) => Task.FromResult(0);

        public Task<int> NotifySecretExpiryAsync(Guid tenantId, IReadOnlyList<KeywardAlertRecipient> recipients, IReadOnlyList<KeywardSecretExpiryLine> lines, CancellationToken ct = default) => Task.FromResult(0);

        public Task<int> NotifyAgentTokenExpiryAsync(Guid tenantId, KeywardAlertRecipient recipient, IReadOnlyList<KeywardAgentTokenExpiryLine> lines, CancellationToken ct = default)
        {
            lock (AgentExpiryRecipients)
            {
                AgentExpiryRecipients.Add(recipient.UserId);
            }

            return Task.FromResult(1);
        }
    }

    // A tenant with an owner, a team vault opened to agents, one Login entry and an agent token (list, read, write, reveal).
    private static async Task<(Guid TenantId, Guid Owner, Guid VaultId, Guid TokenId, Guid ItemId)> SeedAgentSetupAsync(ServiceProvider provider, string itemName)
    {
        var tenantId = Guid.NewGuid();
        var owner = Guid.NewGuid();
        await SeedTenantAsync(provider, tenantId, (owner, TenantRole.Member));
        using var scope = ScopeFor(provider, tenantId, owner);
        var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
        var vaultId = await vaults.CreateTenantVaultAsync(new CreateTenantVaultCommand(owner, tenantId, "team"));
        await vaults.SetAgentAccessAsync(owner, vaultId, allowed: true);
        var itemId = await vaults.AddItemAsync(new AddVaultItemCommand(owner, vaultId, null, ItemType.Login, itemName,
            LoginContent.ToJson("https://db.example", "root", "s3cret", "note")));
        var issued = await scope.ServiceProvider.GetRequiredService<IAgentTokenService>().IssueAsync(new IssueAgentTokenCommand(
            owner, tenantId, $"agent-{Guid.NewGuid():N}",
            AgentScopes.VaultList | AgentScopes.VaultRead | AgentScopes.VaultWrite | AgentScopes.VaultReveal, [vaultId]));
        return (tenantId, owner, vaultId, issued.TokenId, itemId);
    }

    private static async Task AsAgentAsync(ServiceProvider provider, Guid tenantId, Guid userId, Guid tokenId, Func<IVaultService, IRevealRequestService, Task> action)
    {
        using var scope = ScopeFor(provider, tenantId, userId);
        scope.ServiceProvider.GetRequiredService<IActorScopeSetter>().SetActor(ActorKind.Agent, tokenId);
        await action(scope.ServiceProvider.GetRequiredService<IVaultService>(), scope.ServiceProvider.GetRequiredService<IRevealRequestService>());
    }

    private static async Task<int> CountAuditAsync(ServiceProvider provider, Guid tenantId, Guid userId, params string[] resourceTypes)
    {
        using var scope = ScopeFor(provider, tenantId, userId);
        return await scope.ServiceProvider.GetRequiredService<KeywardDbContext>().AuditEntries
            .CountAsync(e => e.TenantId == tenantId && resourceTypes.Contains(e.ResourceType));
    }

    private static async Task<Guid> SeedSoftwareClientTokenAsync(ServiceProvider provider, Guid tenantId)
    {
        using var scope = provider.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
        var token = new SoftwareClientToken(Guid.NewGuid(), tenantId, Guid.NewGuid(), Guid.NewGuid(), "client", "", "", null, DateTimeOffset.UtcNow, null);
        db.SoftwareClientTokens.Add(token);
        await db.SaveChangesAsync();
        return token.Id;
    }

    private static async Task SeedTenantAsync(ServiceProvider provider, Guid tenantId, params (Guid UserId, TenantRole Role)[] users)
    {
        using var scope = provider.CreateScope();
        scope.ServiceProvider.GetRequiredService<ITenantScopeSetter>().SetTenant(tenantId);
        var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
        db.Tenants.Add(new Tenant(tenantId, "review3-data", isSystemTenant: false, DateTimeOffset.UtcNow));
        foreach (var (userId, role) in users)
        {
            var user = new AppUser(userId, issuer: null, externalId: $"user-{userId:N}", displayName: "review3", isSystemAdmin: false, DateTimeOffset.UtcNow);
            user.SetTokenAccessAlertNotification(true);
            user.SetMonitoringNotification(true);
            db.Users.Add(user);
            db.TenantMemberships.Add(new TenantMembership(Guid.NewGuid(), tenantId, userId, role, DateTimeOffset.UtcNow));
        }

        await db.SaveChangesAsync();
    }

    private static IServiceScope ScopeFor(ServiceProvider provider, Guid? tenantId, Guid? userId)
    {
        var scope = provider.CreateScope();
        scope.ServiceProvider.GetRequiredService<ITenantScopeSetter>().SetTenant(tenantId);
        scope.ServiceProvider.GetRequiredService<IUserScopeSetter>().SetUser(userId);
        return scope;
    }

    private static ServiceProvider BuildProvider(Action<IServiceCollection>? configure = null)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddKeyward(ConnectionString, RandomNumberGenerator.GetBytes(32), "test-kek:v1");
        configure?.Invoke(services);
        return services.BuildServiceProvider();
    }

    private static async Task<bool> CanConnectAsync(ServiceProvider provider)
    {
        using var scope = provider.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<KeywardDbContext>().Database.CanConnectAsync();
    }
}
