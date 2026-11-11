using System.Linq.Expressions;
using System.Security.Cryptography;
using System.Text;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Access;
using Am.Keyward.Core.Domain.Agent;
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
/// <para>
/// Reads load only an item's CURRENT version (never the whole history), and every plaintext buffer is zeroed after
/// use. Operations that place something into a folder run in one transaction that reads the folder under a shared
/// lock held to commit, so a concurrent folder deletion can never leave an item or folder pointing at a folder that
/// no longer exists (FolderId / ParentFolderId carry no foreign key).
/// </para>
/// </summary>
public sealed class VaultService(
    IDbContextFactory<KeywardDbContext> dbFactory,
    ISecretBackend backend,
    DbAuditSink audit,
    IClock clock,
    ICurrentTenant tenant,
    ICurrentUser currentUser,
    IKeywardAccessPolicy authorization,
    ICurrentActor actor) : IVaultService
{
    private const int AlgVersion = 1;

    /// <summary>The agent token acting, when the caller is an AI agent (null for a person or the system).</summary>
    private Guid? AgentTokenId => actor is { Kind: ActorKind.Agent, TokenId: { } tokenId } ? tokenId : null;

    // --- personal vaults ---

    public async Task<Guid> CreatePersonalVaultAsync(CreatePersonalVaultCommand cmd, CancellationToken ct = default)
    {
        EnsureUserScope(cmd.UserId);

        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var vault = new Vault(
            Guid.NewGuid(), tenantId: null, OwnerType.User, ownerId: cmd.UserId,
            ProtectionMode.ServerSide, cmd.Name, clock.UtcNow);

        db.Vaults.Add(vault);
        await audit.AppendAsync(db, new AuditRequest(null, AuditAction.Create, "Vault", vault.Id, cmd.UserId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
        return vault.Id;
    }

    public async Task<IReadOnlyList<VaultSummary>> ListVaultsAsync(Guid userId, CancellationToken ct = default)
    {
        EnsureUserScope(userId);

        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        return await db.Vaults
            .Where(v => v.OwnerUserId == userId) // personal vaults
            .OrderBy(v => v.Name)
            .Select(v => new VaultSummary(v.Id, v.Name, v.ProtectionMode, v.CreatedAt, v.AgentAccessAllowed))
            .ToListAsync(ct)
            .ConfigureAwait(false);
    }

    // --- tenant ("team") vaults + sharing ---

    public async Task<Guid> CreateTenantVaultAsync(CreateTenantVaultCommand cmd, CancellationToken ct = default)
    {
        EnsureUserScope(cmd.UserId);
        EnsureTenantScope(cmd.TenantId);
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        await EnsureTenantParticipantAsync(db, cmd.UserId, ct).ConfigureAwait(false);

        var vault = new Vault(
            Guid.NewGuid(), cmd.TenantId, OwnerType.Tenant, ownerId: cmd.TenantId,
            ProtectionMode.ServerSide, cmd.Name, clock.UtcNow);
        db.Vaults.Add(vault);

        // The creator gets Manage so they can use and share the vault.
        db.AccessGrants.Add(new AccessGrant(
            Guid.NewGuid(), cmd.TenantId, PrincipalType.User, cmd.UserId,
            new GrantScope(GrantScopeKind.Vault, vault.Id), Permission.Manage, cmd.UserId, clock.UtcNow));

        await audit.AppendAsync(db, new AuditRequest(cmd.TenantId, AuditAction.Create, "Vault", vault.Id, cmd.UserId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
        return vault.Id;
    }

    public async Task<IReadOnlyList<VaultSummary>> ListSharedVaultsAsync(Guid userId, Guid tenantId, CancellationToken ct = default)
    {
        EnsureUserScope(userId);
        EnsureTenantScope(tenantId);
        // No membership gate here: the grant filter below already returns only the vaults this user was
        // granted, so a non-member (or a software-manager-only role) naturally gets an empty list — the same
        // result an outsider in another tenant sees. The membership gate lives on CREATE, where it matters.

        // Direct user grants plus grants held by any group the user belongs to.
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
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
            .Select(v => new VaultSummary(v.Id, v.Name, v.ProtectionMode, v.CreatedAt, v.AgentAccessAllowed))
            .ToListAsync(ct)
            .ConfigureAwait(false);
    }

    public async Task SetAgentAccessAsync(Guid userId, Guid vaultId, bool allowed, CancellationToken ct = default)
    {
        EnsureUserScope(userId);
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var vault = await LoadAuthorizedVaultAsync(db, userId, vaultId, Permission.Manage, ct).ConfigureAwait(false);

        if (allowed) { vault.AllowAgentAccess(); } else { vault.DenyAgentAccess(); }

        await audit.AppendAsync(db, new AuditRequest(vault.TenantId, allowed ? AuditAction.Grant : AuditAction.Revoke, "VaultAgentAccess", vault.Id, userId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public async Task ShareWithUserAsync(ShareVaultWithUserCommand cmd, CancellationToken ct = default)
    {
        EnsureUserScope(cmd.ActorUserId);
        EnsureTenantScope(cmd.TenantId);
        await UpsertGrantAsync(cmd.ActorUserId, cmd.TenantId, cmd.VaultId, PrincipalType.User, cmd.GranteeUserId, cmd.Permission,
            // Users are installation-global: the grantee must be a member of THIS tenant (the same rule that builds
            // the share candidate list), otherwise a caller could grant a team vault to another tenant's user.
            async (db, innerCt) =>
            {
                if (!await db.TenantMemberships.AnyAsync(m => m.TenantId == cmd.TenantId && m.UserId == cmd.GranteeUserId, innerCt).ConfigureAwait(false))
                {
                    throw new InvalidOperationException($"User {cmd.GranteeUserId} is not a member of tenant {cmd.TenantId}.");
                }
            },
            ct).ConfigureAwait(false);
    }

    public async Task ShareWithGroupAsync(ShareVaultWithGroupCommand cmd, CancellationToken ct = default)
    {
        EnsureUserScope(cmd.ActorUserId);
        EnsureTenantScope(cmd.TenantId);
        await UpsertGrantAsync(cmd.ActorUserId, cmd.TenantId, cmd.VaultId, PrincipalType.Group, cmd.GroupId, cmd.Permission,
            async (db, innerCt) =>
            {
                if (!await db.Groups.AnyAsync(g => g.Id == cmd.GroupId && g.TenantId == cmd.TenantId, innerCt).ConfigureAwait(false))
                {
                    throw new InvalidOperationException($"Group {cmd.GroupId} not found in tenant {cmd.TenantId}.");
                }
            },
            ct).ConfigureAwait(false);
    }

    // One grant per (principal, vault): an existing grant changes its permission, a missing one is added. Two
    // concurrent shares to the same principal both see «missing»; the unique index lets one insert win, and the loser
    // retries once on a fresh context, where it now finds the grant and updates it — so a double submit or two admins
    // sharing at once end in one grant with the last permission, never in a duplicate row or an error.
    private async Task UpsertGrantAsync(
        Guid actorUserId, Guid tenantId, Guid vaultId, PrincipalType principalType, Guid principalId, Permission permission,
        Func<KeywardDbContext, CancellationToken, Task> validatePrincipal, CancellationToken ct)
    {
        for (var attempt = 1; ; attempt++)
        {
            await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
            await LoadAuthorizedVaultAsync(db, actorUserId, vaultId, Permission.Manage, ct).ConfigureAwait(false);
            await validatePrincipal(db, ct).ConfigureAwait(false);

            var existing = await db.AccessGrants.FirstOrDefaultAsync(
                g => g.PrincipalType == principalType && g.PrincipalId == principalId
                  && g.Scope.Kind == GrantScopeKind.Vault && g.Scope.TargetId == vaultId, ct)
                .ConfigureAwait(false);

            if (existing is not null)
            {
                existing.ChangePermission(permission);
            }
            else
            {
                db.AccessGrants.Add(new AccessGrant(
                    Guid.NewGuid(), tenantId, principalType, principalId,
                    new GrantScope(GrantScopeKind.Vault, vaultId), permission, actorUserId, clock.UtcNow));
            }

            await audit.AppendAsync(db, new AuditRequest(tenantId, AuditAction.Grant, "Vault", vaultId, actorUserId), ct).ConfigureAwait(false);
            try
            {
                await db.SaveChangesAsync(ct).ConfigureAwait(false);
                return;
            }
            catch (DbUpdateException ex) when (attempt == 1 && existing is null && ex.IsUniqueViolationOn(AccessGrantUniqueIndex))
            {
                // Lost the insert race to a concurrent share of the same principal — retry as an update.
            }
            catch (DbUpdateException ex) when (ex.IsUniqueViolationOn(AccessGrantUniqueIndex))
            {
                throw new InvalidOperationException("The vault's sharing was changed at the same time; reload and try again.", ex);
            }
        }
    }

    /// <summary>The unique index on (PrincipalType, PrincipalId, ScopeKind, ScopeTargetId) — see the Review3DataIntegrity migration.</summary>
    internal const string AccessGrantUniqueIndex = "UX_AccessGrants_Principal_Scope";

    public async Task RevokeShareAsync(Guid actorUserId, Guid tenantId, Guid vaultId, PrincipalType principalType, Guid principalId, CancellationToken ct = default)
    {
        EnsureUserScope(actorUserId);
        EnsureTenantScope(tenantId);
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        await LoadAuthorizedVaultAsync(db, actorUserId, vaultId, Permission.Manage, ct).ConfigureAwait(false);

        var grants = await db.AccessGrants
            .Where(g => g.PrincipalType == principalType && g.PrincipalId == principalId
                && g.Scope.Kind == GrantScopeKind.Vault && g.Scope.TargetId == vaultId)
            .ToListAsync(ct).ConfigureAwait(false);
        if (grants.Count == 0)
        {
            return;
        }

        db.AccessGrants.RemoveRange(grants);
        await audit.AppendAsync(db, new AuditRequest(tenantId, AuditAction.Revoke, "Vault", vaultId, actorUserId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<ShareCandidate>> ListShareCandidatesAsync(Guid actorUserId, Guid tenantId, CancellationToken ct = default)
    {
        EnsureUserScope(actorUserId);
        EnsureTenantScope(tenantId);

        // Users are installation-global, so candidates are scoped by explicit tenant membership — a user
        // from another tenant (or test residue in a shared database) must never appear in a share list.
        // Exclude the actor.
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
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
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        await LoadAuthorizedVaultAsync(db, actorUserId, vaultId, Permission.Manage, ct).ConfigureAwait(false);

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

    public Task<Guid> AddFolderAsync(AddVaultFolderCommand cmd, CancellationToken ct = default)
    {
        EnsureUserScope(cmd.UserId);
        return RunAsync(transactional: cmd.ParentFolderId is not null, async (db, innerCt) =>
        {
            var vault = await LoadAuthorizedVaultAsync(db, cmd.UserId, cmd.VaultId, Permission.Write, innerCt).ConfigureAwait(false);

            // A parent must exist in the SAME vault — a cross-vault parent would break the tree invariant. Read under a
            // shared lock held to commit, so a concurrent deletion of the parent cannot orphan the new folder.
            if (cmd.ParentFolderId is { } parentId && !await FolderExistsLockedAsync(db, parentId, cmd.VaultId, innerCt).ConfigureAwait(false))
            {
                throw new InvalidOperationException($"Parent folder {parentId} not found in vault {cmd.VaultId}.");
            }

            var folder = vault.AddFolder(Guid.NewGuid(), cmd.Name, clock.UtcNow, cmd.ParentFolderId);
            db.Folders.Add(folder); // new child of a tracked aggregate (app-assigned key) -> mark Added explicitly
            await audit.AppendAsync(db, new AuditRequest(vault.TenantId, AuditAction.Update, "Vault", vault.Id, cmd.UserId), innerCt).ConfigureAwait(false);
            await db.SaveChangesAsync(innerCt).ConfigureAwait(false);
            return folder.Id;
        }, ct);
    }

    public Task<Guid> AddItemAsync(AddVaultItemCommand cmd, CancellationToken ct = default)
    {
        EnsureUserScope(cmd.UserId);
        return RunAsync(transactional: cmd.FolderId is not null, async (db, innerCt) =>
        {
            var vault = await LoadAuthorizedVaultAsync(db, cmd.UserId, cmd.VaultId, Permission.Write, innerCt).ConfigureAwait(false);
            await EnsureFolderInVaultAsync(db, cmd.FolderId, vault.Id, innerCt).ConfigureAwait(false);
            if (cmd.Type == ItemType.Login)
            {
                LoginContent.EnsureValid(cmd.Content);
            }

            var item = new VaultItem(
                Guid.NewGuid(), vault.Id, vault.TenantId, vault.OwnerUserId, cmd.FolderId, cmd.Type, cmd.Name, cmd.UserId, clock.UtcNow);

            var versionId = Guid.NewGuid();
            var aad = Aad.ForVaultItemVersion(vault.TenantId, vault.OwnerType, vault.OwnerId, item.Id, versionId, AlgVersion);
            item.AddVersion(versionId, await EncryptAsync(cmd.Content, aad, innerCt).ConfigureAwait(false), clock.UtcNow);

            db.VaultItems.Add(item); // new aggregate -> whole graph Added
            await audit.AppendAsync(db, new AuditRequest(vault.TenantId, AuditAction.Create, "VaultItem", item.Id, cmd.UserId), innerCt).ConfigureAwait(false);
            await db.SaveChangesAsync(innerCt).ConfigureAwait(false);
            return item.Id;
        }, ct);
    }

    public async Task<string?> ReadItemAsync(Guid userId, Guid itemId, CancellationToken ct = default)
    {
        EnsureUserScope(userId);

        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var (item, current) = await LoadItemAsync(db, i => i.Id == itemId, tracking: false, ct).ConfigureAwait(false);
        if (item is null || current is null)
        {
            return null;
        }

        var vault = await LoadAuthorizedVaultAsync(db, userId, item.VaultId, Permission.Read, ct).ConfigureAwait(false);
        var content = await DecryptCurrentAsync(vault, item, current, ct).ConfigureAwait(false);

        await audit.AppendAsync(db, new AuditRequest(vault.TenantId, AuditAction.Read, "VaultItem", item.Id, userId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
        return content;
    }

    public async Task<IReadOnlyList<VaultFolderSummary>> ListFoldersAsync(Guid userId, Guid vaultId, CancellationToken ct = default)
    {
        EnsureUserScope(userId);
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var vault = await LoadAuthorizedVaultAsync(db, userId, vaultId, Permission.Read, ct).ConfigureAwait(false);

        var folders = await db.Folders
            .Where(f => f.VaultId == vaultId)
            .OrderBy(f => f.Name)
            .Select(f => new VaultFolderSummary(f.Id, f.Name, f.CreatedAt, f.ParentFolderId))
            .ToListAsync(ct)
            .ConfigureAwait(false);

        await AuditAgentListingAsync(db, vault, userId, ct).ConfigureAwait(false);
        return folders;
    }

    public async Task<IReadOnlyList<VaultItemSummary>> ListItemsAsync(Guid userId, Guid vaultId, CancellationToken ct = default)
    {
        EnsureUserScope(userId);
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var vault = await LoadAuthorizedVaultAsync(db, userId, vaultId, Permission.Read, ct).ConfigureAwait(false);

        var items = await db.VaultItems
            .Where(i => i.VaultId == vaultId)
            .OrderBy(i => i.Name)
            .Select(i => new VaultItemSummary(i.Id, i.FolderId, i.Type, i.Name, i.CreatedAt))
            .ToListAsync(ct)
            .ConfigureAwait(false);

        await AuditAgentListingAsync(db, vault, userId, ct).ConfigureAwait(false);
        return items;
    }

    // An AI agent enumerating a vault leaves a trail (VaultList); a person browsing the UI does not — every render of
    // the tree would otherwise write to the chain, and a person's opens are audited per item anyway.
    private async Task AuditAgentListingAsync(KeywardDbContext db, Vault vault, Guid userId, CancellationToken ct)
    {
        if (AgentTokenId is null)
        {
            return;
        }

        await audit.AppendAsync(db, new AuditRequest(vault.TenantId, AuditAction.Read, "VaultList", vault.Id, userId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public async Task RenameVaultAsync(Guid userId, Guid vaultId, string name, CancellationToken ct = default)
    {
        EnsureUserScope(userId);
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var vault = await LoadAuthorizedVaultAsync(db, userId, vaultId, Permission.Manage, ct).ConfigureAwait(false);
        vault.Rename(name);
        await audit.AppendAsync(db, new AuditRequest(vault.TenantId, AuditAction.Update, "Vault", vault.Id, userId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public async Task DeleteVaultAsync(Guid userId, Guid vaultId, CancellationToken ct = default)
    {
        EnsureUserScope(userId);
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var vault = await LoadAuthorizedVaultAsync(db, userId, vaultId, Permission.Manage, ct).ConfigureAwait(false);

        // Remove the vault's access grants (no FK to clean them up automatically), then the vault itself
        // (folders / items / versions cascade).
        var grants = await db.AccessGrants
            .Where(g => g.Scope.Kind == GrantScopeKind.Vault && g.Scope.TargetId == vaultId)
            .ToListAsync(ct).ConfigureAwait(false);
        db.AccessGrants.RemoveRange(grants);
        db.Vaults.Remove(vault);

        await audit.AppendAsync(db, new AuditRequest(vault.TenantId, AuditAction.Delete, "Vault", vault.Id, userId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public async Task RenameFolderAsync(Guid userId, Guid vaultId, Guid folderId, string name, CancellationToken ct = default)
    {
        EnsureUserScope(userId);
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var vault = await LoadAuthorizedVaultAsync(db, userId, vaultId, Permission.Write, ct).ConfigureAwait(false);
        var folder = await db.Folders.FirstOrDefaultAsync(f => f.Id == folderId && f.VaultId == vaultId, ct).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Folder {folderId} not found.");
        folder.Rename(name);
        await audit.AppendAsync(db, new AuditRequest(vault.TenantId, AuditAction.Update, "Vault", vault.Id, userId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public async Task DeleteFolderAsync(Guid userId, Guid vaultId, Guid folderId, CancellationToken ct = default)
    {
        EnsureUserScope(userId);
        await RunAsync(transactional: true, async (db, innerCt) =>
        {
            var vault = await LoadAuthorizedVaultAsync(db, userId, vaultId, Permission.Write, innerCt).ConfigureAwait(false);

            // Deleting a folder keeps its contents: items AND child folders move up to the deleted folder's parent
            // (vault root when it had none). FolderId/ParentFolderId carry no FK, so this is explicit — and it is ONE
            // transaction with the audit entry. The folder row goes FIRST: its exclusive lock makes a concurrent «add
            // into this folder» (which reads the folder under a shared lock, see FolderExistsLockedAsync) either finish
            // before us — then its item is moved up below — or wait and then find the folder gone. No dangling FolderId.
            var parentOfDeleted = await db.Folders
                .Where(f => f.Id == folderId && f.VaultId == vaultId)
                .Select(f => new { f.ParentFolderId })
                .FirstOrDefaultAsync(innerCt).ConfigureAwait(false);
            if (parentOfDeleted is null)
            {
                return false; // already gone — nothing to move, nothing to audit
            }

            await db.Folders.Where(f => f.Id == folderId && f.VaultId == vaultId).ExecuteDeleteAsync(innerCt).ConfigureAwait(false);
            await db.VaultItems
                .Where(i => i.VaultId == vaultId && i.FolderId == folderId)
                .ExecuteUpdateAsync(s => s
                    .SetProperty(i => i.FolderId, parentOfDeleted.ParentFolderId)
                    .SetProperty(i => i.Revision, i => Guid.NewGuid()), innerCt)
                .ConfigureAwait(false);
            await db.Folders
                .Where(f => f.VaultId == vaultId && f.ParentFolderId == folderId)
                .ExecuteUpdateAsync(s => s.SetProperty(f => f.ParentFolderId, parentOfDeleted.ParentFolderId), innerCt)
                .ConfigureAwait(false);

            await audit.AppendAsync(db, new AuditRequest(vault.TenantId, AuditAction.Update, "Vault", vault.Id, userId), innerCt).ConfigureAwait(false);
            await db.SaveChangesAsync(innerCt).ConfigureAwait(false);
            return true;
        }, ct).ConfigureAwait(false);
    }

    public async Task UpdateItemAsync(UpdateVaultItemCommand cmd, CancellationToken ct = default)
    {
        EnsureUserScope(cmd.UserId);

        Guid baselineRevision = default;
        try
        {
            await RunAsync(transactional: cmd.FolderId is not null, async (db, innerCt) =>
            {
                var (item, _) = await LoadItemAsync(db, i => i.Id == cmd.ItemId, tracking: true, innerCt).ConfigureAwait(false);
                if (item is null)
                {
                    throw new InvalidOperationException($"Item {cmd.ItemId} not found.");
                }

                baselineRevision = item.Revision;
                if (cmd.ExpectedVersionId is { } expected && item.Revision != expected)
                {
                    throw new VaultItemVersionConflictException(item.Id);
                }

                var vault = await LoadAuthorizedVaultAsync(db, cmd.UserId, item.VaultId, Permission.Write, innerCt).ConfigureAwait(false);
                await EnsureFolderInVaultAsync(db, cmd.FolderId, vault.Id, innerCt).ConfigureAwait(false);
                if (item.Type == ItemType.Login)
                {
                    LoginContent.EnsureValid(cmd.Content);
                }

                item.Rename(cmd.Name, AgentTokenId);
                item.MoveToFolder(cmd.FolderId);

                var versionId = Guid.NewGuid();
                var aad = Aad.ForVaultItemVersion(vault.TenantId, vault.OwnerType, vault.OwnerId, item.Id, versionId, AlgVersion);
                var version = item.AddVersion(versionId, await EncryptAsync(cmd.Content, aad, innerCt).ConfigureAwait(false), clock.UtcNow);
                db.VaultItemVersions.Add(version); // new version of a tracked item -> mark Added explicitly

                await VoidOwnPendingRevealRequestsAsync(db, item.Id, innerCt).ConfigureAwait(false);
                await audit.AppendAsync(db, new AuditRequest(vault.TenantId, AuditAction.Update, "VaultItem", item.Id, cmd.UserId), innerCt).ConfigureAwait(false);
                await db.SaveChangesAsync(innerCt).ConfigureAwait(false);
                return true;
            }, ct).ConfigureAwait(false);
        }
        catch (DbUpdateException ex) when (baselineRevision != default)
        {
            // A concurrent change (rename, move or new value) won between our read and our write — the same outcome as
            // an explicit stale ExpectedVersionId, never a silent overwrite or a raw database error.
            if (await MovedPastAsync(cmd.ItemId, baselineRevision, ex, ct).ConfigureAwait(false))
            {
                throw new VaultItemVersionConflictException(cmd.ItemId);
            }

            throw;
        }
    }

    // An item's folder must belong to the item's own vault: FolderId carries no FK, and a folder from another vault
    // would make the item vanish from its vault's tree (and survive that folder's deletion unparented). Read under a
    // shared lock held to commit — callers that place into a folder run in a transaction (RunAsync) — see DeleteFolderAsync.
    private static async Task EnsureFolderInVaultAsync(KeywardDbContext db, Guid? folderId, Guid vaultId, CancellationToken ct)
    {
        if (folderId is { } id && !await FolderExistsLockedAsync(db, id, vaultId, ct).ConfigureAwait(false))
        {
            throw new InvalidOperationException($"Folder {id} not found in vault {vaultId}.");
        }
    }

    // HOLDLOCK keeps the shared lock on the folder row (or the empty key range) until the surrounding transaction ends,
    // which is what serializes «put something into folder F» against «delete folder F». Row-level security still filters.
    private static async Task<bool> FolderExistsLockedAsync(KeywardDbContext db, Guid folderId, Guid vaultId, CancellationToken ct) =>
        await db.Database
            .SqlQuery<int>($"SELECT COUNT(*) AS [Value] FROM [amkeyward].[Folders] WITH (HOLDLOCK) WHERE [Id] = {folderId} AND [VaultId] = {vaultId}")
            .SingleAsync(ct)
            .ConfigureAwait(false) > 0;

    public Task<Guid> MoveItemAsync(Guid userId, Guid itemId, Guid targetVaultId, Guid? targetFolderId, CancellationToken ct = default)
    {
        EnsureUserScope(userId);
        return RunAsync(transactional: targetFolderId is not null, async (db, innerCt) =>
        {
            var movedId = await MoveItemCoreAsync(db, userId, itemId, targetVaultId, targetFolderId, innerCt).ConfigureAwait(false);
            await db.SaveChangesAsync(innerCt).ConfigureAwait(false);
            return movedId;
        }, ct);
    }

    public async Task MoveItemsAsync(Guid userId, IReadOnlyList<Guid> itemIds, Guid targetVaultId, Guid? targetFolderId, CancellationToken ct = default)
    {
        EnsureUserScope(userId);
        await RunAsync(transactional: targetFolderId is not null, async (db, innerCt) =>
        {
            foreach (var itemId in itemIds.Distinct())
            {
                await MoveItemCoreAsync(db, userId, itemId, targetVaultId, targetFolderId, innerCt).ConfigureAwait(false);
            }

            // One SaveChanges (and one transaction) for the whole batch: either every item moves or none does.
            await db.SaveChangesAsync(innerCt).ConfigureAwait(false);
            return true;
        }, ct).ConfigureAwait(false);
    }

    public Task<Guid> MoveFolderAsync(Guid userId, Guid folderId, Guid targetVaultId, Guid? targetParentFolderId, CancellationToken ct = default)
    {
        EnsureUserScope(userId);
        return RunAsync(transactional: targetParentFolderId is not null,
            (db, innerCt) => MoveFolderCoreAsync(db, userId, folderId, targetVaultId, targetParentFolderId, innerCt), ct);
    }

    private async Task<Guid> MoveFolderCoreAsync(KeywardDbContext db, Guid userId, Guid folderId, Guid targetVaultId, Guid? targetParentFolderId, CancellationToken ct)
    {
        var folder = await db.Folders.FirstOrDefaultAsync(f => f.Id == folderId, ct).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Folder {folderId} not found.");
        var sourceVault = await LoadAuthorizedVaultAsync(db, userId, folder.VaultId, Permission.Write, ct).ConfigureAwait(false);
        var targetVault = await LoadAuthorizedVaultAsync(db, userId, targetVaultId, Permission.Write, ct).ConfigureAwait(false);
        EnsureAgentMayMoveBetween(sourceVault, targetVault);

        if (targetParentFolderId is { } parentId && !await FolderExistsLockedAsync(db, parentId, targetVaultId, ct).ConfigureAwait(false))
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
            await audit.AppendAsync(db, new AuditRequest(sourceVault.TenantId, AuditAction.Update, "Folder", folder.Id, userId), ct).ConfigureAwait(false);
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

        await audit.AppendAsync(db, new AuditRequest(sourceVault.TenantId, AuditAction.Update, "Folder", folder.Id, userId), ct).ConfigureAwait(false);
        await audit.AppendAsync(db, new AuditRequest(targetVault.TenantId, AuditAction.Create, "Folder", idMap[folder.Id], userId), ct).ConfigureAwait(false);

        var subtreeIds = subtree.Select(f => f.Id).ToList();
        var itemEntries = await db.VaultItems
            .Where(i => i.VaultId == sourceVault.Id && i.FolderId != null && subtreeIds.Contains(i.FolderId.Value))
            .Select(i => new { i.Id, FolderId = i.FolderId!.Value })
            .ToListAsync(ct).ConfigureAwait(false);
        foreach (var entry in itemEntries)
        {
            await MoveItemCoreAsync(db, userId, entry.Id, targetVaultId, idMap[entry.FolderId], ct).ConfigureAwait(false);
        }

        db.Folders.RemoveRange(subtree);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
        return idMap[folder.Id];
    }

    // An AI agent may move entries between the vaults it reaches, but never take a TEAM entry into a PERSONAL vault:
    // that would pull a shared credential out of the tenant's grants and audit chain into a place only the token's
    // user sees. A person may (it is their own deliberate act in the UI).
    private void EnsureAgentMayMoveBetween(Vault source, Vault target)
    {
        if (AgentTokenId is not null && source.TenantId is not null && target.TenantId is null)
        {
            throw new InvalidOperationException("An AI agent cannot move a team vault entry into a personal vault.");
        }
    }

    private async Task<Guid> MoveItemCoreAsync(KeywardDbContext db, Guid userId, Guid itemId, Guid targetVaultId, Guid? targetFolderId, CancellationToken ct)
    {
        var item = await db.VaultItems.FirstOrDefaultAsync(i => i.Id == itemId, ct).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Item {itemId} not found.");
        var sourceVault = await LoadAuthorizedVaultAsync(db, userId, item.VaultId, Permission.Write, ct).ConfigureAwait(false);
        var targetVault = await LoadAuthorizedVaultAsync(db, userId, targetVaultId, Permission.Write, ct).ConfigureAwait(false);
        EnsureAgentMayMoveBetween(sourceVault, targetVault);

        // The target folder must live in the TARGET vault. It may be a not-yet-saved clone from a
        // folder-subtree move, so the change tracker counts as much as the database.
        if (targetFolderId is { } folderId
            && !db.Folders.Local.Any(f => f.Id == folderId && f.VaultId == targetVaultId)
            && !await FolderExistsLockedAsync(db, folderId, targetVaultId, ct).ConfigureAwait(false))
        {
            throw new InvalidOperationException($"Folder {folderId} not found in vault {targetVaultId}.");
        }

        if (sourceVault.Id == targetVault.Id)
        {
            // Same vault: a plain folder change — the ciphertext's binding is unaffected.
            item.MoveToFolder(targetFolderId);
            await audit.AppendAsync(db, new AuditRequest(sourceVault.TenantId, AuditAction.Update, "VaultItem", item.Id, userId), ct).ConfigureAwait(false);
            return item.Id;
        }

        // Across vaults: every version's ciphertext is cryptographically bound (AAD) to its vault/owner/item/version,
        // so each is decrypted under the source binding and re-encrypted under the target's — the WHOLE history moves
        // along, with its numbers and dates. New item id in the target (the id is part of the binding); the source item
        // is removed. One SaveChanges keeps the move atomic.
        if (item.CurrentVersionId is null)
        {
            throw new InvalidOperationException($"Item {itemId} has no content version.");
        }

        var history = await db.VaultItemVersions
            .Where(v => v.VaultItemId == item.Id)
            .OrderBy(v => v.VersionNumber)
            .ToListAsync(ct).ConfigureAwait(false);

        var moved = new VaultItem(
            Guid.NewGuid(), targetVault.Id, targetVault.TenantId, targetVault.OwnerUserId, targetFolderId, item.Type, item.Name, userId, clock.UtcNow);
        moved.AdoptLineageOf(item); // stable deep link + agent rename marker survive the move

        foreach (var version in history)
        {
            var sourceAad = Aad.ForVaultItemVersion(sourceVault.TenantId, sourceVault.OwnerType, sourceVault.OwnerId, item.Id, version.Id, AlgVersion);
            var plaintext = await backend.UnprotectAsync(version.Encrypted, sourceAad, ct).ConfigureAwait(false);
            try
            {
                var newVersionId = Guid.NewGuid();
                var targetAad = Aad.ForVaultItemVersion(targetVault.TenantId, targetVault.OwnerType, targetVault.OwnerId, moved.Id, newVersionId, AlgVersion);
                var encrypted = await backend.ProtectAsync(plaintext, targetAad, ct).ConfigureAwait(false);
                moved.CarryOverVersion(newVersionId, version.VersionNumber, encrypted, version.CreatedAt, isCurrent: version.Id == item.CurrentVersionId);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }

        db.VaultItems.Add(moved);
        db.VaultItems.Remove(item); // the loaded versions are deleted with it

        await audit.AppendAsync(db, new AuditRequest(sourceVault.TenantId, AuditAction.Delete, "VaultItem", item.Id, userId), ct).ConfigureAwait(false);
        await audit.AppendAsync(db, new AuditRequest(targetVault.TenantId, AuditAction.Create, "VaultItem", moved.Id, userId), ct).ConfigureAwait(false);
        return moved.Id;
    }

    public async Task DeleteItemAsync(Guid userId, Guid itemId, CancellationToken ct = default)
    {
        EnsureUserScope(userId);

        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var item = await db.VaultItems.FirstOrDefaultAsync(i => i.Id == itemId, ct).ConfigureAwait(false);
        if (item is null)
        {
            return;
        }

        var vault = await LoadAuthorizedVaultAsync(db, userId, item.VaultId, Permission.Write, ct).ConfigureAwait(false);
        db.VaultItems.Remove(item); // versions cascade

        await audit.AppendAsync(db, new AuditRequest(vault.TenantId, AuditAction.Delete, "VaultItem", item.Id, userId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public Task<VaultItemDetail?> GetItemAsync(Guid userId, Guid itemId, CancellationToken ct = default) =>
        GetItemDetailAsync(userId, i => i.Id == itemId, ct);

    public Task<VaultItemDetail?> GetItemByPublicIdAsync(Guid userId, Guid publicId, CancellationToken ct = default) =>
        GetItemDetailAsync(userId, i => i.PublicId == publicId, ct);

    private async Task<VaultItemDetail?> GetItemDetailAsync(Guid userId, Expression<Func<VaultItem, bool>> match, CancellationToken ct)
    {
        EnsureUserScope(userId);

        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var (item, current) = await LoadItemAsync(db, match, tracking: false, ct).ConfigureAwait(false);
        if (item is null || current is null)
        {
            return null;
        }

        var vault = await LoadAuthorizedVaultAsync(db, userId, item.VaultId, Permission.Read, ct).ConfigureAwait(false);
        var content = await DecryptCurrentAsync(vault, item, current, ct).ConfigureAwait(false);

        await audit.AppendAsync(db, new AuditRequest(vault.TenantId, AuditAction.Read, "VaultItem", item.Id, userId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);

        return new VaultItemDetail(item.Id, item.VaultId, item.FolderId, item.Type, item.Name, content, item.PublicId, item.Revision);
    }

    public async Task<IReadOnlyList<VaultItemSearchHit>> SearchItemNamesAsync(
        Guid userId, IReadOnlyCollection<Guid> vaultIds, string query, int limit = 100, CancellationToken ct = default)
    {
        EnsureUserScope(userId);

        var q = query?.Trim() ?? "";
        if (q.Length < 2 || vaultIds.Count == 0)
        {
            return [];
        }

        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        // One authorization round-trip for all vaults instead of one per vault; an unreachable one still throws.
        var vaults = await LoadReadableVaultsAsync(db, userId, vaultIds, ct).ConfigureAwait(false);
        var vaultNames = vaults.ToDictionary(v => v.Id, v => v.Name);

        var ids = vaultNames.Keys.ToList();
        var items = await db.VaultItems.AsNoTracking()
            .Where(i => ids.Contains(i.VaultId) && i.Name.Contains(q))
            .OrderBy(i => i.Name)
            .Take(limit)
            .Select(i => new { i.Id, i.VaultId, i.FolderId, i.Type, i.Name })
            .ToListAsync(ct)
            .ConfigureAwait(false);

        // An agent's search is audited (once per audit chain it touched), a person's is not — see the interface.
        if (AgentTokenId is not null)
        {
            foreach (var chain in vaults.Select(v => v.TenantId).Distinct())
            {
                await audit.AppendAsync(db, new AuditRequest(chain, AuditAction.Read, "VaultSearch", null, userId), ct).ConfigureAwait(false);
            }

            await db.SaveChangesAsync(ct).ConfigureAwait(false);
        }

        return items
            .Select(i => new VaultItemSearchHit(i.VaultId, vaultNames[i.VaultId], i.Id, i.FolderId, i.Type, i.Name, "Name"))
            .ToList();
    }

    public async Task<VaultItemMetadata?> GetItemMetadataAsync(Guid userId, Guid itemId, CancellationToken ct = default)
    {
        EnsureUserScope(userId);

        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var (item, current) = await LoadItemAsync(db, i => i.Id == itemId, tracking: false, ct).ConfigureAwait(false);
        if (item is null || current is null)
        {
            return null;
        }

        var vault = await LoadAuthorizedVaultAsync(db, userId, item.VaultId, Permission.Read, ct).ConfigureAwait(false);

        string? url = null, username = null;
        var hasTotp = false;
        if (item.Type == ItemType.Login)
        {
            // Decrypted in memory only to lift the two non-secret fields; password and note never leave here.
            var fields = LoginContent.Parse(await DecryptCurrentAsync(vault, item, current, ct).ConfigureAwait(false));
            url = fields.Url;
            username = fields.Username;
            hasTotp = fields.Totp.Length > 0;

            await audit.AppendAsync(db, new AuditRequest(vault.TenantId, AuditAction.Read, "VaultItemMetadata", item.Id, userId), ct).ConfigureAwait(false);
            await db.SaveChangesAsync(ct).ConfigureAwait(false);
        }

        return new VaultItemMetadata(item.Id, item.VaultId, item.FolderId, item.Type, item.Name, item.PublicId, item.Revision, url, username, hasTotp);
    }

    public async Task<VaultItemReference?> GetItemReferenceAsync(Guid userId, Guid itemId, CancellationToken ct = default)
    {
        EnsureUserScope(userId);

        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var item = await db.VaultItems.AsNoTracking()
            .Where(i => i.Id == itemId)
            .Select(i => new { i.Id, i.VaultId, i.PublicId, i.CurrentVersionId, i.Revision })
            .FirstOrDefaultAsync(ct).ConfigureAwait(false);
        if (item?.CurrentVersionId is null)
        {
            return null;
        }

        await LoadAuthorizedVaultAsync(db, userId, item.VaultId, Permission.Read, ct).ConfigureAwait(false);
        return new VaultItemReference(item.Id, item.PublicId, item.Revision);
    }

    public async Task<VaultItemReference> PatchItemAsync(PatchVaultItemCommand cmd, CancellationToken ct = default)
    {
        EnsureUserScope(cmd.UserId);

        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var (item, current) = await LoadItemAsync(db, i => i.Id == cmd.ItemId, tracking: true, ct).ConfigureAwait(false);
        if (item is null)
        {
            throw new InvalidOperationException($"Item {cmd.ItemId} not found.");
        }

        var vault = await LoadAuthorizedVaultAsync(db, cmd.UserId, item.VaultId, Permission.Write, ct).ConfigureAwait(false);

        // The expected version is the item's REVISION, so a rename or move made in between counts as a change too.
        if (item.Revision != cmd.ExpectedVersionId)
        {
            throw new VaultItemVersionConflictException(item.Id);
        }

        var isLogin = item.Type == ItemType.Login;
        var loginFieldGiven = cmd.Url is not null || cmd.Username is not null || cmd.Password is not null || cmd.Note is not null || cmd.Totp is not null;
        if (!isLogin && loginFieldGiven)
        {
            throw new ArgumentException("Url, username, password, note and totp apply to a Login only; set value instead.");
        }

        if (isLogin && cmd.Value is not null)
        {
            throw new ArgumentException("A Login is changed field by field (url, username, password, note, totp), not by value.");
        }

        if (cmd.Name is null && !loginFieldGiven && cmd.Value is null)
        {
            throw new ArgumentException("Nothing to change.");
        }

        if (cmd.Name is not null)
        {
            item.Rename(cmd.Name, AgentTokenId);
        }

        if (loginFieldGiven || cmd.Value is not null)
        {
            string content;
            if (isLogin)
            {
                // The current fields are needed to keep what the caller does not change; decrypted in memory only
                // and deliberately not audited as a Read, since nothing is returned to the caller.
                var fields = current is null
                    ? LoginContent.Parse(null)
                    : LoginContent.Parse(await DecryptCurrentAsync(vault, item, current, ct).ConfigureAwait(false));
                content = LoginContent.ToJson(
                    cmd.Url ?? fields.Url, cmd.Username ?? fields.Username, cmd.Password ?? fields.Password, cmd.Note ?? fields.Note,
                    cmd.Totp ?? fields.Totp);
            }
            else
            {
                content = cmd.Value!;
            }

            var versionId = Guid.NewGuid();
            var aad = Aad.ForVaultItemVersion(vault.TenantId, vault.OwnerType, vault.OwnerId, item.Id, versionId, AlgVersion);
            var version = item.AddVersion(versionId, await EncryptAsync(content, aad, ct).ConfigureAwait(false), clock.UtcNow);
            db.VaultItemVersions.Add(version); // new version of a tracked item -> mark Added explicitly
        }

        // The token changed the item: whatever it asked to reveal before is no longer what the person would approve.
        await VoidOwnPendingRevealRequestsAsync(db, item.Id, ct).ConfigureAwait(false);

        await audit.AppendAsync(db, new AuditRequest(vault.TenantId, AuditAction.Update, "VaultItem", item.Id, cmd.UserId), ct).ConfigureAwait(false);
        try
        {
            await db.SaveChangesAsync(ct).ConfigureAwait(false);
        }
        catch (DbUpdateException ex)
        {
            // Another writer moved the item past the expected revision between our read and our write. Depending on
            // which statement loses, that surfaces as the concurrency token (UPDATE of Revision finds no row) or as
            // the unique (VaultItemId, VersionNumber) index on the new version row.
            if (await MovedPastAsync(cmd.ItemId, cmd.ExpectedVersionId, ex, ct).ConfigureAwait(false))
            {
                throw new VaultItemVersionConflictException(item.Id);
            }

            throw;
        }

        return new VaultItemReference(item.Id, item.PublicId, item.Revision);
    }

    // When an AI agent changes an item, its OWN still-pending reveal requests for that item are voided: the person
    // would otherwise approve a request whose subject (name or value) the requester has just altered.
    private async Task VoidOwnPendingRevealRequestsAsync(KeywardDbContext db, Guid itemId, CancellationToken ct)
    {
        if (AgentTokenId is not { } tokenId)
        {
            return;
        }

        var now = clock.UtcNow;
        var pending = await db.RevealRequests
            .Where(r => r.TokenId == tokenId && r.ItemId == itemId && r.Status == RevealRequestStatus.Pending)
            .ToListAsync(ct).ConfigureAwait(false);
        foreach (var request in pending)
        {
            request.Void(now);
        }
    }

    // Decides whether a failed save lost a race: true when the item's revision is no longer the one the change
    // started from. Anything else is a real failure and propagates unchanged.
    private async Task<bool> MovedPastAsync(Guid itemId, Guid baselineRevision, DbUpdateException ex, CancellationToken ct)
    {
        if (ex is DbUpdateConcurrencyException)
        {
            return true;
        }

        await using var fresh = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var current = await fresh.VaultItems.AsNoTracking()
            .Where(i => i.Id == itemId)
            .Select(i => (Guid?)i.Revision)
            .FirstOrDefaultAsync(ct)
            .ConfigureAwait(false);
        return current != baselineRevision;
    }

    public async Task<string?> RevealFieldAsync(Guid userId, Guid itemId, RevealField field, string reason, CancellationToken ct = default)
    {
        EnsureUserScope(userId);

        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var (item, current) = await LoadItemAsync(db, i => i.Id == itemId, tracking: false, ct).ConfigureAwait(false);
        if (item is null || current is null)
        {
            return null;
        }

        var vault = await LoadAuthorizedVaultAsync(db, userId, item.VaultId, Permission.Read, ct).ConfigureAwait(false);
        var content = await DecryptCurrentAsync(vault, item, current, ct).ConfigureAwait(false);

        var value = (item.Type, field) switch
        {
            (ItemType.Login, RevealField.Password) => LoginContent.Parse(content).Password,
            (ItemType.Login, RevealField.Note) => LoginContent.Parse(content).Note,
            (ItemType.Login, RevealField.Totp) => CurrentCode(content).Code,
            (not ItemType.Login, RevealField.Value) => content,
            _ => throw new ArgumentException($"A {item.Type} has no field {field}."),
        };

        await audit.AppendAsync(db, new AuditRequest(vault.TenantId, AuditAction.Reveal, "VaultItem", item.Id, userId, reason), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
        return value;
    }

    public async Task<TotpCode?> GenerateTotpCodeAsync(Guid userId, Guid itemId, string reason, CancellationToken ct = default)
    {
        EnsureUserScope(userId);

        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var (item, current) = await LoadItemAsync(db, i => i.Id == itemId, tracking: false, ct).ConfigureAwait(false);
        if (item is null || current is null)
        {
            return null;
        }

        var vault = await LoadAuthorizedVaultAsync(db, userId, item.VaultId, Permission.Read, ct).ConfigureAwait(false);
        if (item.Type != ItemType.Login)
        {
            throw new ArgumentException($"A {item.Type} has no one-time code.");
        }

        var code = CurrentCode(await DecryptCurrentAsync(vault, item, current, ct).ConfigureAwait(false));

        await audit.AppendAsync(db, new AuditRequest(vault.TenantId, AuditAction.Reveal, "VaultItemTotp", item.Id, userId, reason), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
        return code;
    }

    // The code of a Login's 2FA key at this moment; the key itself never leaves the service.
    private TotpCode CurrentCode(string loginContent) =>
        LoginContent.Parse(loginContent).Totp is { Length: > 0 } key
            ? Totp.Generate(key, clock.UtcNow)
            : throw new ArgumentException("This login has no 2FA key.");

    public async Task<VaultItemLink?> ResolveItemLinkAsync(Guid userId, Guid publicId, CancellationToken ct = default)
    {
        EnsureUserScope(userId);

        // Routing only — no decryption, no read-audit (the open goes through GetItemAsync). AsNoTracking:
        // read-only lookup.
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var item = await db.VaultItems.AsNoTracking()
            .Where(i => i.PublicId == publicId)
            .Select(i => new { i.Id, i.VaultId })
            .FirstOrDefaultAsync(ct).ConfigureAwait(false);
        if (item is null)
        {
            return null;
        }

        // Enforce the same read gate as an open, so a link never reveals an item the user cannot read.
        var vault = await LoadAuthorizedVaultOrNullAsync(db, userId, item.VaultId, Permission.Read, ct).ConfigureAwait(false);
        if (vault is null)
        {
            return null;
        }

        return new VaultItemLink(item.Id, item.VaultId, vault.TenantId is not null);
    }

    public async Task<IReadOnlyList<ImportedLogin>> ExportVaultLoginsAsync(Guid userId, Guid vaultId, CancellationToken ct = default)
    {
        EnsureUserScope(userId);
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var vault = await LoadAuthorizedVaultAsync(db, userId, vaultId, Permission.Read, ct).ConfigureAwait(false);

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

        var items = await CurrentValuesAsync(db, [vaultId], ItemType.Login, ct).ConfigureAwait(false);

        var result = new List<ImportedLogin>(items.Count);
        foreach (var item in items.OrderBy(i => i.Name))
        {
            var aad = Aad.ForVaultItemVersion(vault.TenantId, vault.OwnerType, vault.OwnerId, item.Id, item.VersionId, AlgVersion);
            var fields = LoginContent.Parse(await DecryptAsync(item.Encrypted, aad, ct).ConfigureAwait(false));
            result.Add(new ImportedLogin(item.Name, fields.Url, fields.Username, fields.Password, fields.Note));
        }

        // One audit event for the export (not one Read per item — see the search rationale).
        await audit.AppendAsync(db, new AuditRequest(vault.TenantId, AuditAction.Read, "VaultExport", vaultId, userId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
        return result;
    }

    public async Task<IReadOnlyList<VaultItemSearchHit>> SearchItemsAsync(Guid userId, Guid tenantId, string query, CancellationToken ct = default)
    {
        EnsureUserScope(userId);

        var q = query?.Trim() ?? "";
        if (q.Length < 2)
        {
            return [];
        }

        // Every vault the user can read: their personal vaults and the team vaults shared with them (decision T13 A).
        // Both lists are already access-filtered (owner / any grant, and Read is the lowest permission), so they are
        // not re-authorized one by one.
        var personal = await ListVaultsAsync(userId, ct).ConfigureAwait(false);
        var shared = await ListSharedVaultsAsync(userId, tenantId, ct).ConfigureAwait(false);
        var summaries = personal.Concat(shared).DistinctBy(v => v.Id).ToList();
        if (summaries.Count == 0)
        {
            return [];
        }

        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var vaultIds = summaries.Select(v => v.Id).ToList();
        var vaults = await db.Vaults.AsNoTracking()
            .Where(v => vaultIds.Contains(v.Id))
            .ToDictionaryAsync(v => v.Id, ct)
            .ConfigureAwait(false);

        // One query for the current value of every item — never the history — and only the columns the match needs.
        var items = await CurrentValuesAsync(db, vaultIds, type: null, ct).ConfigureAwait(false);

        var hits = new List<VaultItemSearchHit>();
        foreach (var item in items.OrderBy(i => i.Name))
        {
            if (!vaults.TryGetValue(item.VaultId, out var vault))
            {
                continue;
            }

            var matched = item.Name.Contains(q, StringComparison.OrdinalIgnoreCase) ? "Name" : null;
            if (matched is null)
            {
                var aad = Aad.ForVaultItemVersion(vault.TenantId, vault.OwnerType, vault.OwnerId, item.Id, item.VersionId, AlgVersion);
                var plaintext = await DecryptAsync(item.Encrypted, aad, ct).ConfigureAwait(false);

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
                hits.Add(new VaultItemSearchHit(vault.Id, vault.Name, item.Id, item.FolderId, item.Type, item.Name, matched));
            }
        }

        // One audit entry per executed search and audit chain it touched — the user's own (personal vaults) and the
        // tenant's (team vaults). A search decrypts many items; auditing each would flood the chain — opening a hit
        // still writes the usual per-item Read.
        if (vaults.Values.Any(v => v.TenantId is null))
        {
            await audit.AppendAsync(db, new AuditRequest(null, AuditAction.Read, "VaultSearch", null, userId), ct).ConfigureAwait(false);
        }

        if (vaults.Values.Any(v => v.TenantId is not null))
        {
            await audit.AppendAsync(db, new AuditRequest(tenantId, AuditAction.Read, "VaultSearch", null, userId), ct).ConfigureAwait(false);
        }

        await db.SaveChangesAsync(ct).ConfigureAwait(false);
        return hits;
    }

    public async Task<int> ImportLoginsAsync(Guid userId, Guid vaultId, IReadOnlyList<ImportedLogin> logins, CancellationToken ct = default)
    {
        EnsureUserScope(userId);
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var vault = await LoadAuthorizedVaultAsync(db, userId, vaultId, Permission.Write, ct).ConfigureAwait(false);

        var imported = 0;
        foreach (var login in logins)
        {
            if (string.IsNullOrWhiteSpace(login.Name) && string.IsNullOrWhiteSpace(login.Url) && string.IsNullOrWhiteSpace(login.Username))
            {
                continue; // skip blank rows
            }

            var name = string.IsNullOrWhiteSpace(login.Name) ? (login.Url is { Length: > 0 } ? login.Url : "Imported login") : login.Name;
            var item = new VaultItem(
                Guid.NewGuid(), vault.Id, vault.TenantId, vault.OwnerUserId, folderId: null, ItemType.Login,
                name.Length > VaultItem.MaxNameLength ? name[..VaultItem.MaxNameLength] : name,
                userId, clock.UtcNow);

            var versionId = Guid.NewGuid();
            var aad = Aad.ForVaultItemVersion(vault.TenantId, vault.OwnerType, vault.OwnerId, item.Id, versionId, AlgVersion);
            var content = LoginContent.ToJson(login.Url, login.Username, login.Password, login.Note,
                Totp.TryParse(login.Totp, out _) ? login.Totp : "");
            item.AddVersion(versionId, await EncryptAsync(content, aad, ct).ConfigureAwait(false), clock.UtcNow);
            db.VaultItems.Add(item);
            imported++;
        }

        if (imported > 0)
        {
            await audit.AppendAsync(db, new AuditRequest(vault.TenantId, AuditAction.Create, "VaultItem", vault.Id, userId), ct).ConfigureAwait(false);
            await db.SaveChangesAsync(ct).ConfigureAwait(false);
        }

        return imported;
    }

    // --- item loading, crypto and transaction helpers ---

    /// <summary>
    /// One item and ONLY its current version (one query, never the history). Tracked when the caller changes the item
    /// (the version is then also fixed up into <see cref="VaultItem.Versions"/>), untracked for reads.
    /// </summary>
    private static async Task<(VaultItem? Item, VaultItemVersion? Current)> LoadItemAsync(
        KeywardDbContext db, Expression<Func<VaultItem, bool>> match, bool tracking, CancellationToken ct)
    {
        var items = tracking ? db.VaultItems : db.VaultItems.AsNoTracking();
        var row = await items
            .Where(match)
            .Select(i => new { Item = i, Current = i.Versions.FirstOrDefault(v => v.Id == i.CurrentVersionId) })
            .FirstOrDefaultAsync(ct)
            .ConfigureAwait(false);
        return (row?.Item, row?.Current);
    }

    private sealed record CurrentValue(Guid Id, Guid VaultId, Guid? FolderId, ItemType Type, string Name, Guid VersionId, EncryptedValue Encrypted);

    /// <summary>The current value of every item of the given vaults (optionally one type) — one query, no history.</summary>
    private static async Task<List<CurrentValue>> CurrentValuesAsync(KeywardDbContext db, IReadOnlyCollection<Guid> vaultIds, ItemType? type, CancellationToken ct)
    {
        var items = db.VaultItems.AsNoTracking().Where(i => vaultIds.Contains(i.VaultId));
        if (type is { } t)
        {
            items = items.Where(i => i.Type == t);
        }

        return await items
            .Join(db.VaultItemVersions.AsNoTracking(), i => i.CurrentVersionId, v => (Guid?)v.Id,
                (i, v) => new CurrentValue(i.Id, i.VaultId, i.FolderId, i.Type, i.Name, v.Id, v.Encrypted))
            .ToListAsync(ct)
            .ConfigureAwait(false);
    }

    private Task<string> DecryptCurrentAsync(Vault vault, VaultItem item, VaultItemVersion current, CancellationToken ct) =>
        DecryptAsync(current.Encrypted, Aad.ForVaultItemVersion(vault.TenantId, vault.OwnerType, vault.OwnerId, item.Id, current.Id, AlgVersion), ct);

    // The plaintext buffer is zeroed as soon as the string exists (a .NET string itself cannot be wiped; keeping the
    // byte copy out of the heap's lifetime is what is possible).
    private async Task<string> DecryptAsync(EncryptedValue encrypted, byte[] aad, CancellationToken ct)
    {
        var plaintext = await backend.UnprotectAsync(encrypted, aad, ct).ConfigureAwait(false);
        try
        {
            return Encoding.UTF8.GetString(plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private async Task<EncryptedValue> EncryptAsync(string content, byte[] aad, CancellationToken ct)
    {
        var plaintext = Encoding.UTF8.GetBytes(content);
        try
        {
            return await backend.ProtectAsync(plaintext, aad, ct).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    /// <summary>
    /// Runs <paramref name="work"/> on a fresh context. With <paramref name="transactional"/> it runs in ONE transaction,
    /// inside the retrying execution strategy (which requires a user transaction to be retried as a whole — each attempt
    /// gets a new context, so no half-tracked state survives into the retry). Used where a check must hold until commit
    /// (a folder something is placed into, see <see cref="FolderExistsLockedAsync"/>) or several statements must commit
    /// with their audit entry (folder deletion). Everything else stays a single SaveChanges — atomic on its own, and
    /// holding no row locks while it waits for the audit-chain lock, which keeps lock chains (and deadlocks) short.
    /// </summary>
    private async Task<T> RunAsync<T>(bool transactional, Func<KeywardDbContext, CancellationToken, Task<T>> work, CancellationToken ct)
    {
        if (!transactional)
        {
            await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
            return await work(db, ct).ConfigureAwait(false);
        }

        await using var outer = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var strategy = outer.Database.CreateExecutionStrategy();
        return await strategy.ExecuteAsync(async innerCt =>
        {
            await using var db = await dbFactory.CreateDbContextAsync(innerCt).ConfigureAwait(false);
            await using var transaction = await db.Database.BeginTransactionAsync(innerCt).ConfigureAwait(false);
            var result = await work(db, innerCt).ConfigureAwait(false);
            await transaction.CommitAsync(innerCt).ConfigureAwait(false);
            return result;
        }, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// The vaults among <paramref name="vaultIds"/> the user may READ, in one round-trip for all tenant vaults (any
    /// grant — direct or through a group — is at least Read). Throws <see cref="UnauthorizedAccessException"/> when one
    /// of them is not readable, like <see cref="LoadAuthorizedVaultAsync"/> does for a single vault.
    /// </summary>
    private async Task<List<Vault>> LoadReadableVaultsAsync(KeywardDbContext db, Guid userId, IReadOnlyCollection<Guid> vaultIds, CancellationToken ct)
    {
        var ids = vaultIds.Distinct().ToList();
        var vaults = await db.Vaults.Where(v => ids.Contains(v.Id)).ToListAsync(ct).ConfigureAwait(false);
        if (vaults.Count != ids.Count)
        {
            throw new InvalidOperationException($"Vault {ids.First(id => vaults.All(v => v.Id != id))} not found.");
        }

        var teamVaultIds = vaults.Where(v => v.OwnerUserId is null).Select(v => v.Id).ToList();
        var granted = new HashSet<Guid>();
        if (teamVaultIds.Count > 0 && tenant.TenantId is not null)
        {
            var groupIds = await db.GroupMemberships
                .Where(m => m.UserId == userId)
                .Select(m => m.GroupId)
                .ToListAsync(ct)
                .ConfigureAwait(false);
            granted = (await db.AccessGrants
                .Where(g => g.Scope.Kind == GrantScopeKind.Vault && teamVaultIds.Contains(g.Scope.TargetId)
                    && ((g.PrincipalType == PrincipalType.User && g.PrincipalId == userId)
                        || (g.PrincipalType == PrincipalType.Group && groupIds.Contains(g.PrincipalId))))
                .Select(g => g.Scope.TargetId)
                .ToListAsync(ct)
                .ConfigureAwait(false)).ToHashSet();
        }

        foreach (var vault in vaults)
        {
            var readable = vault.OwnerUserId is { } owner ? owner == userId : granted.Contains(vault.Id);
            if (!readable)
            {
                throw new UnauthorizedAccessException("Not authorized to Read this vault.");
            }
        }

        return vaults;
    }

    /// <summary>
    /// Loads a vault the current user may access at <paramref name="permission"/>: personal vaults are
    /// owner-only; tenant vaults require a matching access grant (via the central authorization service).
    /// </summary>
    private async Task<Vault> LoadAuthorizedVaultAsync(KeywardDbContext db, Guid userId, Guid vaultId, Permission permission, CancellationToken ct)
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
    private async Task<Vault?> LoadAuthorizedVaultOrNullAsync(KeywardDbContext db, Guid userId, Guid vaultId, Permission permission, CancellationToken ct)
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

    // CREATING a team (tenant-owned) vault requires the user to belong to the current tenant — a system admin,
    // or a member. A bound user that is NOT a tenant member (e.g. a host role granted only the
    // software-manager capability) therefore cannot create one, and — since share candidates are tenant
    // members — can never be granted one either, so team vaults stay entirely outside its reach. LIST/READ are
    // already grant-filtered (a non-member simply sees nothing), and personal vaults are tenant-LESS and
    // owner-owned (gated by the owner scope alone), so the check lives here on create only.
    private async Task EnsureTenantParticipantAsync(KeywardDbContext db, Guid userId, CancellationToken ct)
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
