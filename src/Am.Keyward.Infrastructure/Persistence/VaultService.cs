using System.Text;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Access;
using Am.Keyward.Core.Domain.Audit;
using Am.Keyward.Core.Domain.Human;
using Am.Keyward.Core.Domain.ValueObjects;
using Microsoft.EntityFrameworkCore;

namespace Am.Keyward.Infrastructure.Persistence;

/// <summary>
/// Human-vaults implementation. Personal vaults are owned by a user and isolated per user; tenant ("team")
/// vaults are owned by a tenant and shared within it via <see cref="AccessGrant"/>s (the creator is granted
/// Manage). Every item version is envelope-encrypted and bound to its slot via AAD. Access decisions for
/// tenant vaults go through the central <see cref="IKeywardAccessPolicy"/>; personal vaults are owner-only.
/// </summary>
public sealed class VaultService(
    KeywardDbContext db,
    ISecretBackend backend,
    IAuditSink audit,
    IClock clock,
    ICurrentTenant tenant,
    ICurrentUser currentUser,
    IKeywardAccessPolicy authorization) : IVaultService
{
    private const int AlgVersion = 1;

    // --- personal vaults ---

    public async Task<Guid> CreatePersonalVaultAsync(CreatePersonalVaultCommand cmd, CancellationToken ct = default)
    {
        EnsureUserScope(cmd.UserId);
        await EnsureTenantParticipantAsync(cmd.UserId, ct).ConfigureAwait(false);

        var vault = new Vault(
            Guid.NewGuid(), tenantId: null, OwnerType.User, ownerId: cmd.UserId,
            ProtectionMode.ServerSide, cmd.Name, clock.UtcNow);

        db.Vaults.Add(vault);
        await audit.AppendAsync(new AuditRequest(null, AuditAction.Create, "Vault", vault.Id, cmd.UserId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
        return vault.Id;
    }

    public async Task<IReadOnlyList<VaultSummary>> ListVaultsAsync(Guid userId, CancellationToken ct = default)
    {
        EnsureUserScope(userId);
        await EnsureTenantParticipantAsync(userId, ct).ConfigureAwait(false);

        return await db.Vaults
            .Where(v => v.OwnerUserId == userId) // personal vaults
            .OrderBy(v => v.Name)
            .Select(v => new VaultSummary(v.Id, v.Name, v.ProtectionMode, v.CreatedAt))
            .ToListAsync(ct)
            .ConfigureAwait(false);
    }

    // --- tenant ("team") vaults + sharing ---

    public async Task<Guid> CreateTenantVaultAsync(CreateTenantVaultCommand cmd, CancellationToken ct = default)
    {
        EnsureUserScope(cmd.UserId);
        EnsureTenantScope(cmd.TenantId);
        await EnsureTenantParticipantAsync(cmd.UserId, ct).ConfigureAwait(false);

        var vault = new Vault(
            Guid.NewGuid(), cmd.TenantId, OwnerType.Tenant, ownerId: cmd.TenantId,
            ProtectionMode.ServerSide, cmd.Name, clock.UtcNow);
        db.Vaults.Add(vault);

        // The creator gets Manage so they can use and share the vault.
        db.AccessGrants.Add(new AccessGrant(
            Guid.NewGuid(), cmd.TenantId, PrincipalType.User, cmd.UserId,
            new GrantScope(GrantScopeKind.Vault, vault.Id), Permission.Manage, cmd.UserId, clock.UtcNow));

        await audit.AppendAsync(new AuditRequest(cmd.TenantId, AuditAction.Create, "Vault", vault.Id, cmd.UserId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
        return vault.Id;
    }

    public async Task<IReadOnlyList<VaultSummary>> ListSharedVaultsAsync(Guid userId, Guid tenantId, CancellationToken ct = default)
    {
        EnsureUserScope(userId);
        EnsureTenantScope(tenantId);
        await EnsureTenantParticipantAsync(userId, ct).ConfigureAwait(false);

        // Direct user grants plus grants held by any group the user belongs to.
        var groupIds = await db.GroupMemberships
            .Where(m => m.UserId == userId)
            .Select(m => m.GroupId)
            .ToListAsync(ct)
            .ConfigureAwait(false);
        var grantedVaultIds = await db.AccessGrants
            .Where(g => g.Scope.Kind == GrantScopeKind.Vault
                && ((g.PrincipalType == PrincipalType.User && g.PrincipalId == userId)
                    || (g.PrincipalType == PrincipalType.Group && groupIds.Contains(g.PrincipalId))))
            .Select(g => g.Scope.TargetId)
            .Distinct()
            .ToListAsync(ct)
            .ConfigureAwait(false);

        return await db.Vaults
            .Where(v => v.TenantId == tenantId && grantedVaultIds.Contains(v.Id))
            .OrderBy(v => v.Name)
            .Select(v => new VaultSummary(v.Id, v.Name, v.ProtectionMode, v.CreatedAt))
            .ToListAsync(ct)
            .ConfigureAwait(false);
    }

    public async Task ShareWithUserAsync(ShareVaultWithUserCommand cmd, CancellationToken ct = default)
    {
        EnsureUserScope(cmd.ActorUserId);
        EnsureTenantScope(cmd.TenantId);
        await LoadAuthorizedVaultAsync(cmd.ActorUserId, cmd.VaultId, Permission.Manage, ct).ConfigureAwait(false);

        var existing = await db.AccessGrants.FirstOrDefaultAsync(
            g => g.PrincipalType == PrincipalType.User && g.PrincipalId == cmd.GranteeUserId
              && g.Scope.Kind == GrantScopeKind.Vault && g.Scope.TargetId == cmd.VaultId, ct)
            .ConfigureAwait(false);

        if (existing is not null)
        {
            existing.ChangePermission(cmd.Permission);
        }
        else
        {
            db.AccessGrants.Add(new AccessGrant(
                Guid.NewGuid(), cmd.TenantId, PrincipalType.User, cmd.GranteeUserId,
                new GrantScope(GrantScopeKind.Vault, cmd.VaultId), cmd.Permission, cmd.ActorUserId, clock.UtcNow));
        }

        await audit.AppendAsync(new AuditRequest(cmd.TenantId, AuditAction.Grant, "Vault", cmd.VaultId, cmd.ActorUserId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public async Task ShareWithGroupAsync(ShareVaultWithGroupCommand cmd, CancellationToken ct = default)
    {
        EnsureUserScope(cmd.ActorUserId);
        EnsureTenantScope(cmd.TenantId);
        await LoadAuthorizedVaultAsync(cmd.ActorUserId, cmd.VaultId, Permission.Manage, ct).ConfigureAwait(false);

        if (!await db.Groups.AnyAsync(g => g.Id == cmd.GroupId && g.TenantId == cmd.TenantId, ct).ConfigureAwait(false))
        {
            throw new InvalidOperationException($"Group {cmd.GroupId} not found in tenant {cmd.TenantId}.");
        }

        var existing = await db.AccessGrants.FirstOrDefaultAsync(
            g => g.PrincipalType == PrincipalType.Group && g.PrincipalId == cmd.GroupId
              && g.Scope.Kind == GrantScopeKind.Vault && g.Scope.TargetId == cmd.VaultId, ct)
            .ConfigureAwait(false);

        if (existing is not null)
        {
            existing.ChangePermission(cmd.Permission);
        }
        else
        {
            db.AccessGrants.Add(new AccessGrant(
                Guid.NewGuid(), cmd.TenantId, PrincipalType.Group, cmd.GroupId,
                new GrantScope(GrantScopeKind.Vault, cmd.VaultId), cmd.Permission, cmd.ActorUserId, clock.UtcNow));
        }

        await audit.AppendAsync(new AuditRequest(cmd.TenantId, AuditAction.Grant, "Vault", cmd.VaultId, cmd.ActorUserId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public async Task RevokeShareAsync(Guid actorUserId, Guid tenantId, Guid vaultId, PrincipalType principalType, Guid principalId, CancellationToken ct = default)
    {
        EnsureUserScope(actorUserId);
        EnsureTenantScope(tenantId);
        await LoadAuthorizedVaultAsync(actorUserId, vaultId, Permission.Manage, ct).ConfigureAwait(false);

        var grants = await db.AccessGrants
            .Where(g => g.PrincipalType == principalType && g.PrincipalId == principalId
                && g.Scope.Kind == GrantScopeKind.Vault && g.Scope.TargetId == vaultId)
            .ToListAsync(ct).ConfigureAwait(false);
        if (grants.Count == 0)
        {
            return;
        }

        db.AccessGrants.RemoveRange(grants);
        await audit.AppendAsync(new AuditRequest(tenantId, AuditAction.Revoke, "Vault", vaultId, actorUserId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<ShareCandidate>> ListShareCandidatesAsync(Guid actorUserId, Guid tenantId, CancellationToken ct = default)
    {
        EnsureUserScope(actorUserId);
        EnsureTenantScope(tenantId);

        // Users are installation-global, so candidates are scoped by explicit tenant membership — a user
        // from another tenant (or test residue in a shared database) must never appear in a share list.
        // Exclude the actor.
        return await db.TenantMemberships
            .Where(m => m.TenantId == tenantId && m.UserId != actorUserId)
            .Join(db.Users, m => m.UserId, u => u.Id, (m, u) => new { u.Id, u.DisplayName })
            .OrderBy(x => x.DisplayName)
            .Select(x => new ShareCandidate(x.Id, x.DisplayName))
            .ToListAsync(ct)
            .ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<VaultShare>> ListVaultSharesAsync(Guid actorUserId, Guid vaultId, CancellationToken ct = default)
    {
        EnsureUserScope(actorUserId);
        await LoadAuthorizedVaultAsync(actorUserId, vaultId, Permission.Manage, ct).ConfigureAwait(false);

        var grants = await db.AccessGrants
            .Where(g => g.Scope.Kind == GrantScopeKind.Vault && g.Scope.TargetId == vaultId)
            .Select(g => new { g.PrincipalType, g.PrincipalId, g.Permission })
            .ToListAsync(ct)
            .ConfigureAwait(false);

        var userIds = grants.Where(g => g.PrincipalType == PrincipalType.User).Select(g => g.PrincipalId).ToList();
        var userNames = await db.Users
            .Where(u => userIds.Contains(u.Id))
            .ToDictionaryAsync(u => u.Id, u => u.DisplayName, ct)
            .ConfigureAwait(false);
        var groupIds = grants.Where(g => g.PrincipalType == PrincipalType.Group).Select(g => g.PrincipalId).ToList();
        var groupNames = await db.Groups
            .Where(g => groupIds.Contains(g.Id))
            .ToDictionaryAsync(g => g.Id, g => g.Name, ct)
            .ConfigureAwait(false);

        return grants
            .Select(g => new VaultShare(
                g.PrincipalType,
                g.PrincipalId,
                g.PrincipalType == PrincipalType.Group
                    ? groupNames.GetValueOrDefault(g.PrincipalId, "?")
                    : userNames.GetValueOrDefault(g.PrincipalId, "?"),
                g.Permission))
            .OrderBy(s => s.PrincipalType)
            .ThenBy(s => s.DisplayName)
            .ToList();
    }

    // --- folders + items (work on personal and tenant vaults; access enforced per vault) ---

    public async Task<Guid> AddFolderAsync(AddVaultFolderCommand cmd, CancellationToken ct = default)
    {
        EnsureUserScope(cmd.UserId);
        var vault = await LoadAuthorizedVaultAsync(cmd.UserId, cmd.VaultId, Permission.Write, ct).ConfigureAwait(false);

        // A parent must exist in the SAME vault — a cross-vault parent would break the tree invariant.
        if (cmd.ParentFolderId is { } parentId
            && !await db.Folders.AnyAsync(f => f.Id == parentId && f.VaultId == cmd.VaultId, ct).ConfigureAwait(false))
        {
            throw new InvalidOperationException($"Parent folder {parentId} not found in vault {cmd.VaultId}.");
        }

        var folder = vault.AddFolder(Guid.NewGuid(), cmd.Name, clock.UtcNow, cmd.ParentFolderId);
        db.Folders.Add(folder); // new child of a tracked aggregate (app-assigned key) -> mark Added explicitly
        await audit.AppendAsync(new AuditRequest(vault.TenantId, AuditAction.Update, "Vault", vault.Id, cmd.UserId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
        return folder.Id;
    }

    public async Task<Guid> AddItemAsync(AddVaultItemCommand cmd, CancellationToken ct = default)
    {
        EnsureUserScope(cmd.UserId);
        var vault = await LoadAuthorizedVaultAsync(cmd.UserId, cmd.VaultId, Permission.Write, ct).ConfigureAwait(false);

        var item = new VaultItem(
            Guid.NewGuid(), vault.Id, vault.TenantId, vault.OwnerUserId, cmd.FolderId, cmd.Type, cmd.Name, cmd.UserId, clock.UtcNow);

        var versionId = Guid.NewGuid();
        var aad = Aad.ForVaultItemVersion(vault.TenantId, vault.OwnerType, vault.OwnerId, item.Id, versionId, AlgVersion);
        var encrypted = await backend.ProtectAsync(Encoding.UTF8.GetBytes(cmd.Content), aad, ct).ConfigureAwait(false);
        item.AddVersion(versionId, encrypted, clock.UtcNow);

        db.VaultItems.Add(item); // new aggregate -> whole graph Added
        await audit.AppendAsync(new AuditRequest(vault.TenantId, AuditAction.Create, "VaultItem", item.Id, cmd.UserId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
        return item.Id;
    }

    public async Task<string?> ReadItemAsync(Guid userId, Guid itemId, CancellationToken ct = default)
    {
        EnsureUserScope(userId);

        var item = await db.VaultItems
            .Include(i => i.Versions)
            .FirstOrDefaultAsync(i => i.Id == itemId, ct)
            .ConfigureAwait(false);
        if (item?.CurrentVersionId is null)
        {
            return null;
        }

        var vault = await LoadAuthorizedVaultAsync(userId, item.VaultId, Permission.Read, ct).ConfigureAwait(false);

        var version = item.Versions.Single(v => v.Id == item.CurrentVersionId);
        var aad = Aad.ForVaultItemVersion(vault.TenantId, vault.OwnerType, vault.OwnerId, item.Id, version.Id, AlgVersion);
        var plaintext = await backend.UnprotectAsync(version.Encrypted, aad, ct).ConfigureAwait(false);

        await audit.AppendAsync(new AuditRequest(vault.TenantId, AuditAction.Read, "VaultItem", item.Id, userId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);

        return Encoding.UTF8.GetString(plaintext);
    }

    public async Task<IReadOnlyList<VaultFolderSummary>> ListFoldersAsync(Guid userId, Guid vaultId, CancellationToken ct = default)
    {
        EnsureUserScope(userId);
        await LoadAuthorizedVaultAsync(userId, vaultId, Permission.Read, ct).ConfigureAwait(false);

        return await db.Folders
            .Where(f => f.VaultId == vaultId)
            .OrderBy(f => f.Name)
            .Select(f => new VaultFolderSummary(f.Id, f.Name, f.CreatedAt, f.ParentFolderId))
            .ToListAsync(ct)
            .ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<VaultItemSummary>> ListItemsAsync(Guid userId, Guid vaultId, CancellationToken ct = default)
    {
        EnsureUserScope(userId);
        await LoadAuthorizedVaultAsync(userId, vaultId, Permission.Read, ct).ConfigureAwait(false);

        return await db.VaultItems
            .Where(i => i.VaultId == vaultId)
            .OrderBy(i => i.Name)
            .Select(i => new VaultItemSummary(i.Id, i.FolderId, i.Type, i.Name, i.CreatedAt))
            .ToListAsync(ct)
            .ConfigureAwait(false);
    }

    public async Task RenameVaultAsync(Guid userId, Guid vaultId, string name, CancellationToken ct = default)
    {
        EnsureUserScope(userId);
        var vault = await LoadAuthorizedVaultAsync(userId, vaultId, Permission.Manage, ct).ConfigureAwait(false);
        vault.Rename(name);
        await audit.AppendAsync(new AuditRequest(vault.TenantId, AuditAction.Update, "Vault", vault.Id, userId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public async Task DeleteVaultAsync(Guid userId, Guid vaultId, CancellationToken ct = default)
    {
        EnsureUserScope(userId);
        var vault = await LoadAuthorizedVaultAsync(userId, vaultId, Permission.Manage, ct).ConfigureAwait(false);

        // Remove the vault's access grants (no FK to clean them up automatically), then the vault itself
        // (folders / items / versions cascade).
        var grants = await db.AccessGrants
            .Where(g => g.Scope.Kind == GrantScopeKind.Vault && g.Scope.TargetId == vaultId)
            .ToListAsync(ct).ConfigureAwait(false);
        db.AccessGrants.RemoveRange(grants);
        db.Vaults.Remove(vault);

        await audit.AppendAsync(new AuditRequest(vault.TenantId, AuditAction.Delete, "Vault", vault.Id, userId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public async Task RenameFolderAsync(Guid userId, Guid vaultId, Guid folderId, string name, CancellationToken ct = default)
    {
        EnsureUserScope(userId);
        var vault = await LoadAuthorizedVaultAsync(userId, vaultId, Permission.Write, ct).ConfigureAwait(false);
        var folder = await db.Folders.FirstOrDefaultAsync(f => f.Id == folderId && f.VaultId == vaultId, ct).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Folder {folderId} not found.");
        folder.Rename(name);
        await audit.AppendAsync(new AuditRequest(vault.TenantId, AuditAction.Update, "Vault", vault.Id, userId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public async Task DeleteFolderAsync(Guid userId, Guid vaultId, Guid folderId, CancellationToken ct = default)
    {
        EnsureUserScope(userId);
        var vault = await LoadAuthorizedVaultAsync(userId, vaultId, Permission.Write, ct).ConfigureAwait(false);

        // Deleting a folder keeps its contents: items AND child folders move up to the deleted folder's
        // parent (vault root when it had none). FolderId/ParentFolderId carry no FK, so this is explicit.
        var parentOfDeleted = await db.Folders
            .Where(f => f.Id == folderId && f.VaultId == vaultId)
            .Select(f => f.ParentFolderId)
            .FirstOrDefaultAsync(ct).ConfigureAwait(false);
        await db.VaultItems
            .Where(i => i.VaultId == vaultId && i.FolderId == folderId)
            .ExecuteUpdateAsync(s => s.SetProperty(i => i.FolderId, parentOfDeleted), ct)
            .ConfigureAwait(false);
        await db.Folders
            .Where(f => f.VaultId == vaultId && f.ParentFolderId == folderId)
            .ExecuteUpdateAsync(s => s.SetProperty(f => f.ParentFolderId, parentOfDeleted), ct)
            .ConfigureAwait(false);
        await db.Folders.Where(f => f.Id == folderId && f.VaultId == vaultId).ExecuteDeleteAsync(ct).ConfigureAwait(false);

        await audit.AppendAsync(new AuditRequest(vault.TenantId, AuditAction.Update, "Vault", vault.Id, userId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public async Task UpdateItemAsync(UpdateVaultItemCommand cmd, CancellationToken ct = default)
    {
        EnsureUserScope(cmd.UserId);

        var item = await db.VaultItems.Include(i => i.Versions)
            .FirstOrDefaultAsync(i => i.Id == cmd.ItemId, ct).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Item {cmd.ItemId} not found.");
        var vault = await LoadAuthorizedVaultAsync(cmd.UserId, item.VaultId, Permission.Write, ct).ConfigureAwait(false);

        item.Rename(cmd.Name);
        item.MoveToFolder(cmd.FolderId);

        var versionId = Guid.NewGuid();
        var aad = Aad.ForVaultItemVersion(vault.TenantId, vault.OwnerType, vault.OwnerId, item.Id, versionId, AlgVersion);
        var encrypted = await backend.ProtectAsync(Encoding.UTF8.GetBytes(cmd.Content), aad, ct).ConfigureAwait(false);
        item.AddVersion(versionId, encrypted, clock.UtcNow);
        db.VaultItemVersions.Add(item.Current); // new version of a tracked item -> mark Added explicitly

        await audit.AppendAsync(new AuditRequest(vault.TenantId, AuditAction.Update, "VaultItem", item.Id, cmd.UserId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public async Task<Guid> MoveItemAsync(Guid userId, Guid itemId, Guid targetVaultId, Guid? targetFolderId, CancellationToken ct = default)
    {
        EnsureUserScope(userId);
        var movedId = await MoveItemCoreAsync(userId, itemId, targetVaultId, targetFolderId, ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
        return movedId;
    }

    public async Task MoveItemsAsync(Guid userId, IReadOnlyList<Guid> itemIds, Guid targetVaultId, Guid? targetFolderId, CancellationToken ct = default)
    {
        EnsureUserScope(userId);
        foreach (var itemId in itemIds.Distinct())
        {
            await MoveItemCoreAsync(userId, itemId, targetVaultId, targetFolderId, ct).ConfigureAwait(false);
        }

        // One SaveChanges for the whole batch: either every item moves or none does.
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public async Task<Guid> MoveFolderAsync(Guid userId, Guid folderId, Guid targetVaultId, Guid? targetParentFolderId, CancellationToken ct = default)
    {
        EnsureUserScope(userId);

        var folder = await db.Folders.FirstOrDefaultAsync(f => f.Id == folderId, ct).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Folder {folderId} not found.");
        var sourceVault = await LoadAuthorizedVaultAsync(userId, folder.VaultId, Permission.Write, ct).ConfigureAwait(false);
        var targetVault = await LoadAuthorizedVaultAsync(userId, targetVaultId, Permission.Write, ct).ConfigureAwait(false);

        if (targetParentFolderId is { } parentId
            && !await db.Folders.AnyAsync(f => f.Id == parentId && f.VaultId == targetVaultId, ct).ConfigureAwait(false))
        {
            throw new InvalidOperationException($"Parent folder {parentId} not found in vault {targetVaultId}.");
        }

        // The moved subtree: the folder itself plus all descendants (needed for the cycle guard and, on a
        // cross-vault move, to take everything along).
        var sourceFolders = await db.Folders.Where(f => f.VaultId == folder.VaultId).ToListAsync(ct).ConfigureAwait(false);
        var subtree = new List<Folder> { folder };
        for (var i = 0; i < subtree.Count; i++)
        {
            subtree.AddRange(sourceFolders.Where(f => f.ParentFolderId == subtree[i].Id));
        }

        if (sourceVault.Id == targetVault.Id)
        {
            // A folder must never become its own ancestor.
            if (targetParentFolderId is { } newParent && subtree.Any(f => f.Id == newParent))
            {
                throw new InvalidOperationException("A folder cannot be moved into itself or one of its subfolders.");
            }

            folder.MoveTo(targetParentFolderId);
            await audit.AppendAsync(new AuditRequest(sourceVault.TenantId, AuditAction.Update, "Folder", folder.Id, userId), ct).ConfigureAwait(false);
            await db.SaveChangesAsync(ct).ConfigureAwait(false);
            return folder.Id;
        }

        // Cross-vault: recreate the folder subtree in the target (new ids, correct isolation keys),
        // re-encrypt every contained item into its mapped folder, remove the old subtree — all flushed by
        // ONE SaveChanges, so the whole move is atomic (the item core's folder check also looks at the
        // change tracker, where the clones live until the save).
        var idMap = new Dictionary<Guid, Guid>();
        foreach (var f in subtree)
        {
            var mappedParent = f.Id == folder.Id
                ? targetParentFolderId
                : idMap[f.ParentFolderId!.Value];
            var clone = targetVault.AddFolder(Guid.NewGuid(), f.Name, clock.UtcNow, mappedParent);
            db.Folders.Add(clone);
            idMap[f.Id] = clone.Id;
        }

        await audit.AppendAsync(new AuditRequest(sourceVault.TenantId, AuditAction.Update, "Folder", folder.Id, userId), ct).ConfigureAwait(false);
        await audit.AppendAsync(new AuditRequest(targetVault.TenantId, AuditAction.Create, "Folder", idMap[folder.Id], userId), ct).ConfigureAwait(false);

        var subtreeIds = subtree.Select(f => f.Id).ToList();
        var itemEntries = await db.VaultItems
            .Where(i => i.VaultId == sourceVault.Id && i.FolderId != null && subtreeIds.Contains(i.FolderId.Value))
            .Select(i => new { i.Id, FolderId = i.FolderId!.Value })
            .ToListAsync(ct).ConfigureAwait(false);
        foreach (var entry in itemEntries)
        {
            await MoveItemCoreAsync(userId, entry.Id, targetVaultId, idMap[entry.FolderId], ct).ConfigureAwait(false);
        }

        db.Folders.RemoveRange(subtree);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
        return idMap[folder.Id];
    }

    private async Task<Guid> MoveItemCoreAsync(Guid userId, Guid itemId, Guid targetVaultId, Guid? targetFolderId, CancellationToken ct)
    {
        var item = await db.VaultItems.Include(i => i.Versions)
            .FirstOrDefaultAsync(i => i.Id == itemId, ct).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Item {itemId} not found.");
        var sourceVault = await LoadAuthorizedVaultAsync(userId, item.VaultId, Permission.Write, ct).ConfigureAwait(false);
        var targetVault = await LoadAuthorizedVaultAsync(userId, targetVaultId, Permission.Write, ct).ConfigureAwait(false);

        // The target folder must live in the TARGET vault. It may be a not-yet-saved clone from a
        // folder-subtree move, so the change tracker counts as much as the database.
        if (targetFolderId is { } folderId
            && !db.Folders.Local.Any(f => f.Id == folderId && f.VaultId == targetVaultId)
            && !await db.Folders.AnyAsync(f => f.Id == folderId && f.VaultId == targetVaultId, ct).ConfigureAwait(false))
        {
            throw new InvalidOperationException($"Folder {folderId} not found in vault {targetVaultId}.");
        }

        if (sourceVault.Id == targetVault.Id)
        {
            // Same vault: a plain folder change — the ciphertext's binding is unaffected.
            item.MoveToFolder(targetFolderId);
            await audit.AppendAsync(new AuditRequest(sourceVault.TenantId, AuditAction.Update, "VaultItem", item.Id, userId), ct).ConfigureAwait(false);
            return item.Id;
        }

        // Across vaults: the version ciphertext is cryptographically bound (AAD) to its vault/owner, so
        // decrypt under the source binding and re-encrypt under the target's. New item id in the target;
        // the source item is removed. One SaveChanges keeps the move atomic.
        if (item.CurrentVersionId is null)
        {
            throw new InvalidOperationException($"Item {itemId} has no content version.");
        }

        var currentVersion = item.Versions.Single(v => v.Id == item.CurrentVersionId);
        var sourceAad = Aad.ForVaultItemVersion(sourceVault.TenantId, sourceVault.OwnerType, sourceVault.OwnerId, item.Id, currentVersion.Id, AlgVersion);
        var plaintext = await backend.UnprotectAsync(currentVersion.Encrypted, sourceAad, ct).ConfigureAwait(false);

        var moved = new VaultItem(
            Guid.NewGuid(), targetVault.Id, targetVault.TenantId, targetVault.OwnerUserId, targetFolderId, item.Type, item.Name, userId, clock.UtcNow);
        moved.AdoptPublicId(item.PublicId); // keep the shareable deep link stable across the vault move
        var versionId = Guid.NewGuid();
        var targetAad = Aad.ForVaultItemVersion(targetVault.TenantId, targetVault.OwnerType, targetVault.OwnerId, moved.Id, versionId, AlgVersion);
        var encrypted = await backend.ProtectAsync(plaintext, targetAad, ct).ConfigureAwait(false);
        moved.AddVersion(versionId, encrypted, clock.UtcNow);

        db.VaultItems.Add(moved);
        db.VaultItems.Remove(item); // versions cascade

        await audit.AppendAsync(new AuditRequest(sourceVault.TenantId, AuditAction.Delete, "VaultItem", item.Id, userId), ct).ConfigureAwait(false);
        await audit.AppendAsync(new AuditRequest(targetVault.TenantId, AuditAction.Create, "VaultItem", moved.Id, userId), ct).ConfigureAwait(false);
        return moved.Id;
    }

    public async Task DeleteItemAsync(Guid userId, Guid itemId, CancellationToken ct = default)
    {
        EnsureUserScope(userId);

        var item = await db.VaultItems.FirstOrDefaultAsync(i => i.Id == itemId, ct).ConfigureAwait(false);
        if (item is null)
        {
            return;
        }

        var vault = await LoadAuthorizedVaultAsync(userId, item.VaultId, Permission.Write, ct).ConfigureAwait(false);
        db.VaultItems.Remove(item); // versions cascade

        await audit.AppendAsync(new AuditRequest(vault.TenantId, AuditAction.Delete, "VaultItem", item.Id, userId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public Task<VaultItemDetail?> GetItemAsync(Guid userId, Guid itemId, CancellationToken ct = default) =>
        GetItemDetailAsync(userId, i => i.Id == itemId, ct);

    public Task<VaultItemDetail?> GetItemByPublicIdAsync(Guid userId, Guid publicId, CancellationToken ct = default) =>
        GetItemDetailAsync(userId, i => i.PublicId == publicId, ct);

    private async Task<VaultItemDetail?> GetItemDetailAsync(
        Guid userId, System.Linq.Expressions.Expression<Func<VaultItem, bool>> match, CancellationToken ct)
    {
        EnsureUserScope(userId);

        var item = await db.VaultItems.Include(i => i.Versions)
            .FirstOrDefaultAsync(match, ct).ConfigureAwait(false);
        if (item?.CurrentVersionId is null)
        {
            return null;
        }

        var vault = await LoadAuthorizedVaultAsync(userId, item.VaultId, Permission.Read, ct).ConfigureAwait(false);

        var version = item.Versions.Single(v => v.Id == item.CurrentVersionId);
        var aad = Aad.ForVaultItemVersion(vault.TenantId, vault.OwnerType, vault.OwnerId, item.Id, version.Id, AlgVersion);
        var plaintext = await backend.UnprotectAsync(version.Encrypted, aad, ct).ConfigureAwait(false);

        await audit.AppendAsync(new AuditRequest(vault.TenantId, AuditAction.Read, "VaultItem", item.Id, userId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);

        return new VaultItemDetail(item.Id, item.VaultId, item.FolderId, item.Type, item.Name, Encoding.UTF8.GetString(plaintext), item.PublicId);
    }

    public async Task<VaultItemLink?> ResolveItemLinkAsync(Guid userId, Guid publicId, CancellationToken ct = default)
    {
        EnsureUserScope(userId);

        // Routing only — no decryption, no read-audit (the open goes through GetItemAsync). AsNoTracking:
        // read-only lookup.
        var item = await db.VaultItems.AsNoTracking()
            .Where(i => i.PublicId == publicId)
            .Select(i => new { i.Id, i.VaultId })
            .FirstOrDefaultAsync(ct).ConfigureAwait(false);
        if (item is null)
        {
            return null;
        }

        // Enforce the same read gate as an open, so a link never reveals an item the user cannot read.
        var vault = await LoadAuthorizedVaultOrNullAsync(userId, item.VaultId, Permission.Read, ct).ConfigureAwait(false);
        if (vault is null)
        {
            return null;
        }

        return new VaultItemLink(item.Id, item.VaultId, vault.TenantId is not null);
    }

    public async Task<IReadOnlyList<ImportedLogin>> ExportVaultLoginsAsync(Guid userId, Guid vaultId, CancellationToken ct = default)
    {
        EnsureUserScope(userId);
        var vault = await LoadAuthorizedVaultAsync(userId, vaultId, Permission.Read, ct).ConfigureAwait(false);

        // A team-vault export disclosed every password at once — tenant admins (or system admins) only;
        // an ordinary Manage grant is deliberately NOT enough.
        if (vault.TenantId is { } tenantId)
        {
            var isOperator = await db.Users.AnyAsync(u => u.Id == userId && u.IsSystemAdmin, ct).ConfigureAwait(false)
                || await db.TenantMemberships.AnyAsync(
                    m => m.TenantId == tenantId && m.UserId == userId && m.Role == TenantRole.TenantAdmin, ct).ConfigureAwait(false);
            if (!isOperator)
            {
                throw new UnauthorizedAccessException("Exporting a team vault requires the tenant-admin role.");
            }
        }

        var items = await db.VaultItems.AsNoTracking().Include(i => i.Versions)
            .Where(i => i.VaultId == vaultId && i.Type == ItemType.Login)
            .OrderBy(i => i.Name)
            .ToListAsync(ct).ConfigureAwait(false);

        var result = new List<ImportedLogin>(items.Count);
        foreach (var item in items)
        {
            if (item.CurrentVersionId is null)
            {
                continue;
            }

            var version = item.Versions.Single(v => v.Id == item.CurrentVersionId);
            var aad = Aad.ForVaultItemVersion(vault.TenantId, vault.OwnerType, vault.OwnerId, item.Id, version.Id, AlgVersion);
            var fields = LoginContent.Parse(Encoding.UTF8.GetString(await backend.UnprotectAsync(version.Encrypted, aad, ct).ConfigureAwait(false)));
            result.Add(new ImportedLogin(item.Name, fields.Url, fields.Username, fields.Password, fields.Note));
        }

        // One audit event for the export (not one Read per item — see the search rationale).
        await audit.AppendAsync(new AuditRequest(vault.TenantId, AuditAction.Read, "VaultExport", vaultId, userId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
        return result;
    }

    public async Task<IReadOnlyList<VaultItemSearchHit>> SearchItemsAsync(Guid userId, Guid tenantId, bool teamVaults, string query, CancellationToken ct = default)
    {
        EnsureUserScope(userId);

        var q = query?.Trim() ?? "";
        if (q.Length < 2)
        {
            return [];
        }

        var vaults = teamVaults
            ? await ListSharedVaultsAsync(userId, tenantId, ct).ConfigureAwait(false)
            : await ListVaultsAsync(userId, ct).ConfigureAwait(false);

        var hits = new List<VaultItemSearchHit>();
        foreach (var vaultSummary in vaults)
        {
            var vault = await LoadAuthorizedVaultAsync(userId, vaultSummary.Id, Permission.Read, ct).ConfigureAwait(false);
            var items = await db.VaultItems.AsNoTracking().Include(i => i.Versions)
                .Where(i => i.VaultId == vaultSummary.Id)
                .OrderBy(i => i.Name)
                .ToListAsync(ct).ConfigureAwait(false);

            foreach (var item in items)
            {
                var matched = item.Name.Contains(q, StringComparison.OrdinalIgnoreCase) ? "Name" : null;

                if (matched is null && item.CurrentVersionId is not null)
                {
                    var version = item.Versions.Single(v => v.Id == item.CurrentVersionId);
                    var aad = Aad.ForVaultItemVersion(vault.TenantId, vault.OwnerType, vault.OwnerId, item.Id, version.Id, AlgVersion);
                    var plaintext = Encoding.UTF8.GetString(await backend.UnprotectAsync(version.Encrypted, aad, ct).ConfigureAwait(false));

                    if (item.Type == ItemType.Login)
                    {
                        // Deliberately NOT the password: matching on it would surprise the user ("why does
                        // this item match?") and quietly confirm password values; standard manager behavior.
                        var fields = LoginContent.Parse(plaintext);
                        matched = fields.Username.Contains(q, StringComparison.OrdinalIgnoreCase) ? "Username"
                            : fields.Url.Contains(q, StringComparison.OrdinalIgnoreCase) ? "Url"
                            : fields.Note.Contains(q, StringComparison.OrdinalIgnoreCase) ? "Note"
                            : null;
                    }
                    else
                    {
                        matched = plaintext.Contains(q, StringComparison.OrdinalIgnoreCase) ? "Value" : null;
                    }
                }

                if (matched is not null)
                {
                    hits.Add(new VaultItemSearchHit(vaultSummary.Id, vaultSummary.Name, item.Id, item.FolderId, item.Type, item.Name, matched));
                }
            }
        }

        // One audit entry per executed search (a search decrypts many items; auditing each would flood the
        // chain — opening a hit still writes the usual per-item Read).
        await audit.AppendAsync(new AuditRequest(teamVaults ? tenantId : null, AuditAction.Read, "VaultSearch", null, userId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);

        return hits;
    }

    public async Task<int> ImportLoginsAsync(Guid userId, Guid vaultId, IReadOnlyList<ImportedLogin> logins, CancellationToken ct = default)
    {
        EnsureUserScope(userId);
        var vault = await LoadAuthorizedVaultAsync(userId, vaultId, Permission.Write, ct).ConfigureAwait(false);

        var imported = 0;
        foreach (var login in logins)
        {
            if (string.IsNullOrWhiteSpace(login.Name) && string.IsNullOrWhiteSpace(login.Url) && string.IsNullOrWhiteSpace(login.Username))
            {
                continue; // skip blank rows
            }

            var item = new VaultItem(
                Guid.NewGuid(), vault.Id, vault.TenantId, vault.OwnerUserId, folderId: null, ItemType.Login,
                string.IsNullOrWhiteSpace(login.Name) ? (login.Url is { Length: > 0 } ? login.Url : "Imported login") : login.Name,
                userId, clock.UtcNow);

            var versionId = Guid.NewGuid();
            var aad = Aad.ForVaultItemVersion(vault.TenantId, vault.OwnerType, vault.OwnerId, item.Id, versionId, AlgVersion);
            var content = LoginContent.ToJson(login.Url, login.Username, login.Password, login.Note);
            var encrypted = await backend.ProtectAsync(Encoding.UTF8.GetBytes(content), aad, ct).ConfigureAwait(false);
            item.AddVersion(versionId, encrypted, clock.UtcNow);
            db.VaultItems.Add(item);
            imported++;
        }

        if (imported > 0)
        {
            await audit.AppendAsync(new AuditRequest(vault.TenantId, AuditAction.Create, "VaultItem", vault.Id, userId), ct).ConfigureAwait(false);
            await db.SaveChangesAsync(ct).ConfigureAwait(false);
        }

        return imported;
    }

    /// <summary>
    /// Loads a vault the current user may access at <paramref name="permission"/>: personal vaults are
    /// owner-only; tenant vaults require a matching access grant (via the central authorization service).
    /// </summary>
    private async Task<Vault> LoadAuthorizedVaultAsync(Guid userId, Guid vaultId, Permission permission, CancellationToken ct)
    {
        var vault = await db.Vaults.FirstOrDefaultAsync(v => v.Id == vaultId, ct).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Vault {vaultId} not found.");

        if (vault.OwnerUserId is not null)
        {
            if (vault.OwnerUserId != userId)
            {
                throw new UnauthorizedAccessException("Not authorized for this vault.");
            }

            return vault;
        }

        var allowed = await authorization
            .IsAllowedAsync(userId, new GrantScope(GrantScopeKind.Vault, vaultId), permission, ct)
            .ConfigureAwait(false);
        if (!allowed)
        {
            throw new UnauthorizedAccessException($"Not authorized to {permission} this vault.");
        }

        return vault;
    }

    /// <summary>Like <see cref="LoadAuthorizedVaultAsync"/> but returns null instead of throwing when the
    /// vault is missing or the user isn't authorized — for the deep-link resolver, where "no access" must be
    /// indistinguishable from "unknown link" rather than an error.</summary>
    private async Task<Vault?> LoadAuthorizedVaultOrNullAsync(Guid userId, Guid vaultId, Permission permission, CancellationToken ct)
    {
        var vault = await db.Vaults.FirstOrDefaultAsync(v => v.Id == vaultId, ct).ConfigureAwait(false);
        if (vault is null)
        {
            return null;
        }

        if (vault.OwnerUserId is not null)
        {
            return vault.OwnerUserId == userId ? vault : null;
        }

        var allowed = await authorization
            .IsAllowedAsync(userId, new GrantScope(GrantScopeKind.Vault, vaultId), permission, ct)
            .ConfigureAwait(false);
        return allowed ? vault : null;
    }

    private void EnsureUserScope(Guid requestedUserId)
    {
        if (currentUser.UserId != requestedUserId)
        {
            throw new UnauthorizedAccessException(
                "User scope mismatch: the request's user does not match the authenticated user.");
        }
    }

    // Using vaults (creating/listing personal or team vaults) requires the user to actually belong to the
    // current tenant — a system admin, or a member of this tenant. A bound user that is NOT a tenant member
    // (e.g. a host role granted only the software-manager capability) therefore has no vault access at all,
    // and — since share candidates are tenant members — can never be granted a team vault either.
    private async Task EnsureTenantParticipantAsync(Guid userId, CancellationToken ct)
    {
        var isParticipant =
            await db.Users.AnyAsync(u => u.Id == userId && u.IsSystemAdmin, ct).ConfigureAwait(false)
            || await db.TenantMemberships.AnyAsync(m => m.TenantId == tenant.TenantId && m.UserId == userId, ct).ConfigureAwait(false);
        if (!isParticipant)
        {
            throw new UnauthorizedAccessException("Vault access requires membership in this tenant.");
        }
    }

    private void EnsureTenantScope(Guid requestedTenantId)
    {
        if (tenant.TenantId != requestedTenantId)
        {
            throw new UnauthorizedAccessException(
                "Tenant scope mismatch: the request's tenant does not match the authenticated scope.");
        }
    }
}
