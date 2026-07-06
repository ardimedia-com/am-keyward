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

        var grantedVaultIds = await db.AccessGrants
            .Where(g => g.PrincipalType == PrincipalType.User && g.PrincipalId == userId && g.Scope.Kind == GrantScopeKind.Vault)
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

    public async Task<IReadOnlyList<ShareCandidate>> ListShareCandidatesAsync(Guid actorUserId, Guid tenantId, CancellationToken ct = default)
    {
        EnsureUserScope(actorUserId);
        EnsureTenantScope(tenantId);

        // Users are installation-global; membership scoping arrives with groups. Exclude the actor.
        return await db.Users
            .Where(u => u.Id != actorUserId)
            .OrderBy(u => u.DisplayName)
            .Select(u => new ShareCandidate(u.Id, u.DisplayName))
            .ToListAsync(ct)
            .ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<VaultShare>> ListVaultSharesAsync(Guid actorUserId, Guid vaultId, CancellationToken ct = default)
    {
        EnsureUserScope(actorUserId);
        await LoadAuthorizedVaultAsync(actorUserId, vaultId, Permission.Manage, ct).ConfigureAwait(false);

        var grants = await db.AccessGrants
            .Where(g => g.PrincipalType == PrincipalType.User && g.Scope.Kind == GrantScopeKind.Vault && g.Scope.TargetId == vaultId)
            .Select(g => new { g.PrincipalId, g.Permission })
            .ToListAsync(ct)
            .ConfigureAwait(false);

        var ids = grants.Select(g => g.PrincipalId).ToList();
        var names = await db.Users
            .Where(u => ids.Contains(u.Id))
            .ToDictionaryAsync(u => u.Id, u => u.DisplayName, ct)
            .ConfigureAwait(false);

        return grants
            .Select(g => new VaultShare(g.PrincipalId, names.GetValueOrDefault(g.PrincipalId, "?"), g.Permission))
            .ToList();
    }

    // --- folders + items (work on personal and tenant vaults; access enforced per vault) ---

    public async Task<Guid> AddFolderAsync(AddVaultFolderCommand cmd, CancellationToken ct = default)
    {
        EnsureUserScope(cmd.UserId);
        var vault = await LoadAuthorizedVaultAsync(cmd.UserId, cmd.VaultId, Permission.Write, ct).ConfigureAwait(false);

        var folder = vault.AddFolder(Guid.NewGuid(), cmd.Name, clock.UtcNow);
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
            .Select(f => new VaultFolderSummary(f.Id, f.Name, f.CreatedAt))
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

        // Move the folder's items back to the vault root (FolderId has no FK), then delete the folder.
        await db.VaultItems
            .Where(i => i.VaultId == vaultId && i.FolderId == folderId)
            .ExecuteUpdateAsync(s => s.SetProperty(i => i.FolderId, (Guid?)null), ct)
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

    public async Task<VaultItemDetail?> GetItemAsync(Guid userId, Guid itemId, CancellationToken ct = default)
    {
        EnsureUserScope(userId);

        var item = await db.VaultItems.Include(i => i.Versions)
            .FirstOrDefaultAsync(i => i.Id == itemId, ct).ConfigureAwait(false);
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

        return new VaultItemDetail(item.Id, item.VaultId, item.FolderId, item.Type, item.Name, Encoding.UTF8.GetString(plaintext));
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

    private void EnsureUserScope(Guid requestedUserId)
    {
        if (currentUser.UserId != requestedUserId)
        {
            throw new UnauthorizedAccessException(
                "User scope mismatch: the request's user does not match the authenticated user.");
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
