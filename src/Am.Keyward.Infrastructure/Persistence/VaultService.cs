using System.Text;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Audit;
using Am.Keyward.Core.Domain.Human;
using Microsoft.EntityFrameworkCore;

namespace Am.Keyward.Infrastructure.Persistence;

/// <summary>
/// Human-vaults implementation (v0.1: personal, server-side-encrypted vaults). Encrypts each item version
/// into the envelope, binding it to its slot (tenant/owner/item/version) via AAD. Access is
/// server-authoritative on the current user; personal-vault isolation is backed in depth by the user-scoped
/// query filter and SQL Server row-level security.
/// </summary>
public sealed class VaultService(
    KeywardDbContext db,
    ISecretBackend backend,
    IAuditSink audit,
    IClock clock,
    ICurrentUser currentUser) : IVaultService
{
    private const int AlgVersion = 1;

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

    public async Task<Guid> AddFolderAsync(AddVaultFolderCommand cmd, CancellationToken ct = default)
    {
        EnsureUserScope(cmd.UserId);

        var vault = await db.Vaults.FirstOrDefaultAsync(v => v.Id == cmd.VaultId, ct).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Vault {cmd.VaultId} not found.");

        var folder = vault.AddFolder(Guid.NewGuid(), cmd.Name, clock.UtcNow);
        db.Folders.Add(folder); // new child of a tracked aggregate (app-assigned key) -> mark Added explicitly
        await audit.AppendAsync(new AuditRequest(vault.TenantId, AuditAction.Update, "Vault", vault.Id, cmd.UserId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
        return folder.Id;
    }

    public async Task<Guid> AddItemAsync(AddVaultItemCommand cmd, CancellationToken ct = default)
    {
        EnsureUserScope(cmd.UserId);

        var vault = await db.Vaults.FirstOrDefaultAsync(v => v.Id == cmd.VaultId, ct).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Vault {cmd.VaultId} not found.");

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

        var vault = await db.Vaults.FirstOrDefaultAsync(v => v.Id == item.VaultId, ct).ConfigureAwait(false);
        if (vault is null)
        {
            return null;
        }

        var version = item.Versions.Single(v => v.Id == item.CurrentVersionId);
        var aad = Aad.ForVaultItemVersion(vault.TenantId, vault.OwnerType, vault.OwnerId, item.Id, version.Id, AlgVersion);
        var plaintext = await backend.UnprotectAsync(version.Encrypted, aad, ct).ConfigureAwait(false);

        await audit.AppendAsync(new AuditRequest(vault.TenantId, AuditAction.Read, "VaultItem", item.Id, userId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);

        return Encoding.UTF8.GetString(plaintext);
    }

    public async Task<IReadOnlyList<VaultSummary>> ListVaultsAsync(Guid userId, CancellationToken ct = default)
    {
        EnsureUserScope(userId);

        return await db.Vaults
            .Where(v => v.OwnerUserId == userId) // personal vaults (v0.1)
            .OrderBy(v => v.Name)
            .Select(v => new VaultSummary(v.Id, v.Name, v.ProtectionMode, v.CreatedAt))
            .ToListAsync(ct)
            .ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<VaultFolderSummary>> ListFoldersAsync(Guid userId, Guid vaultId, CancellationToken ct = default)
    {
        EnsureUserScope(userId);

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

        return await db.VaultItems
            .Where(i => i.VaultId == vaultId)
            .OrderBy(i => i.Name)
            .Select(i => new VaultItemSummary(i.Id, i.FolderId, i.Type, i.Name, i.CreatedAt))
            .ToListAsync(ct)
            .ConfigureAwait(false);
    }

    /// <summary>Server-authoritative: the request's user must match the ambient authenticated user.</summary>
    private void EnsureUserScope(Guid requestedUserId)
    {
        if (currentUser.UserId != requestedUserId)
        {
            throw new UnauthorizedAccessException(
                "User scope mismatch: the request's user does not match the authenticated user.");
        }
    }
}
