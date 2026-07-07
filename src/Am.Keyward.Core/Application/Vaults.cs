using System.Text.Json;
using Am.Keyward.Core.Domain;

namespace Am.Keyward.Core.Application;

/// <summary>Creates a personal (tenant-less, user-owned) vault.</summary>
public sealed record CreatePersonalVaultCommand(Guid UserId, string Name);

/// <summary>Creates a tenant-owned ("team") vault; the creator is granted Manage on it.</summary>
public sealed record CreateTenantVaultCommand(Guid UserId, Guid TenantId, string Name);

/// <summary>Shares a tenant vault with another user at a permission level (actor must have Manage).</summary>
public sealed record ShareVaultWithUserCommand(Guid ActorUserId, Guid TenantId, Guid VaultId, Guid GranteeUserId, Permission Permission);

/// <summary>A user who can be granted access to a tenant vault.</summary>
public sealed record ShareCandidate(Guid UserId, string DisplayName);

/// <summary>An existing share on a vault (a user or a group, per PrincipalType).</summary>
public sealed record VaultShare(PrincipalType PrincipalType, Guid PrincipalId, string DisplayName, Permission Permission);

/// <summary>Shares a tenant vault with a group at a permission level (actor must have Manage).</summary>
public sealed record ShareVaultWithGroupCommand(Guid ActorUserId, Guid TenantId, Guid VaultId, Guid GroupId, Permission Permission);

/// <summary>Adds a folder to a vault the user owns.</summary>
public sealed record AddVaultFolderCommand(Guid UserId, Guid VaultId, string Name, Guid? ParentFolderId = null);

/// <summary>Adds a typed item to a vault, encrypting its content into a new version.</summary>
public sealed record AddVaultItemCommand(Guid UserId, Guid VaultId, Guid? FolderId, ItemType Type, string Name, string Content);

/// <summary>Updates an item's name/folder and stores its new content as a new encrypted version.</summary>
public sealed record UpdateVaultItemCommand(Guid UserId, Guid ItemId, string Name, Guid? FolderId, string Content);

public sealed record VaultSummary(Guid Id, string Name, ProtectionMode ProtectionMode, DateTimeOffset CreatedAt);

public sealed record VaultItemSummary(Guid Id, Guid? FolderId, ItemType Type, string Name, DateTimeOffset CreatedAt);

/// <summary>An item plus its decrypted content (for viewing/editing).</summary>
public sealed record VaultItemDetail(Guid Id, Guid VaultId, Guid? FolderId, ItemType Type, string Name, string Content);

public sealed record VaultFolderSummary(Guid Id, string Name, DateTimeOffset CreatedAt, Guid? ParentFolderId = null);

/// <summary>A login parsed from an import file (e.g. a Microsoft Edge / Chrome password export).</summary>
public sealed record ImportedLogin(string Name, string Url, string Username, string Password, string Note);

/// <summary>
/// The structured content of a Login item: url / username / password / note, stored as JSON inside the
/// item's encrypted value (the item's Name is the cleartext title). Other item types store their content
/// as-is. Keeping this in one place lets the UI and the importer compose/parse it identically.
/// </summary>
public static class LoginContent
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public sealed record Fields(string Url, string Username, string Password, string Note);

    public static string ToJson(string url, string username, string password, string note) =>
        JsonSerializer.Serialize(new Fields(url ?? "", username ?? "", password ?? "", note ?? ""), Json);

    public static Fields Parse(string? content)
    {
        if (string.IsNullOrWhiteSpace(content))
        {
            return new Fields("", "", "", "");
        }

        try
        {
            return JsonSerializer.Deserialize<Fields>(content, Json) ?? new Fields("", "", "", "");
        }
        catch (JsonException)
        {
            // Not structured JSON (e.g. a plain note migrated in) — treat the whole thing as the note.
            return new Fields("", "", "", content);
        }
    }
}

/// <summary>
/// Application service for human vaults: personal (user-owned) and tenant ("team", grant-shared) vaults,
/// each server-side encrypted. Full CRUD on vaults, folders and items. Access is server-authoritative on
/// the current user; tenant vaults additionally require an access grant (read/write/manage).
/// </summary>
public interface IVaultService
{
    // Vaults
    Task<Guid> CreatePersonalVaultAsync(CreatePersonalVaultCommand command, CancellationToken ct = default);
    Task<Guid> CreateTenantVaultAsync(CreateTenantVaultCommand command, CancellationToken ct = default);
    Task<IReadOnlyList<VaultSummary>> ListVaultsAsync(Guid userId, CancellationToken ct = default);

    /// <summary>Tenant ("team") vaults the user has been granted access to (includes ones they created).</summary>
    Task<IReadOnlyList<VaultSummary>> ListSharedVaultsAsync(Guid userId, Guid tenantId, CancellationToken ct = default);

    Task RenameVaultAsync(Guid userId, Guid vaultId, string name, CancellationToken ct = default);
    Task DeleteVaultAsync(Guid userId, Guid vaultId, CancellationToken ct = default);

    // Sharing (tenant vaults)
    Task ShareWithUserAsync(ShareVaultWithUserCommand command, CancellationToken ct = default);
    Task ShareWithGroupAsync(ShareVaultWithGroupCommand command, CancellationToken ct = default);

    /// <summary>Removes a user's or group's grant on a vault (actor must have Manage).</summary>
    Task RevokeShareAsync(Guid actorUserId, Guid tenantId, Guid vaultId, PrincipalType principalType, Guid principalId, CancellationToken ct = default);

    /// <summary>Users in the tenant the actor can share a vault with (excludes the actor).</summary>
    Task<IReadOnlyList<ShareCandidate>> ListShareCandidatesAsync(Guid actorUserId, Guid tenantId, CancellationToken ct = default);

    Task<IReadOnlyList<VaultShare>> ListVaultSharesAsync(Guid actorUserId, Guid vaultId, CancellationToken ct = default);

    // Folders
    Task<Guid> AddFolderAsync(AddVaultFolderCommand command, CancellationToken ct = default);
    Task RenameFolderAsync(Guid userId, Guid vaultId, Guid folderId, string name, CancellationToken ct = default);
    Task DeleteFolderAsync(Guid userId, Guid vaultId, Guid folderId, CancellationToken ct = default);
    Task<IReadOnlyList<VaultFolderSummary>> ListFoldersAsync(Guid userId, Guid vaultId, CancellationToken ct = default);

    // Items
    Task<Guid> AddItemAsync(AddVaultItemCommand command, CancellationToken ct = default);
    Task UpdateItemAsync(UpdateVaultItemCommand command, CancellationToken ct = default);
    Task DeleteItemAsync(Guid userId, Guid itemId, CancellationToken ct = default);
    Task<IReadOnlyList<VaultItemSummary>> ListItemsAsync(Guid userId, Guid vaultId, CancellationToken ct = default);

    /// <summary>An item with its decrypted content (for view/edit). Null if not found / not accessible.</summary>
    Task<VaultItemDetail?> GetItemAsync(Guid userId, Guid itemId, CancellationToken ct = default);

    /// <summary>
    /// Moves an item into another folder and/or another vault (the user needs Write on both sides). Within
    /// a vault this is a folder change; across vaults the content is decrypted and re-encrypted under the
    /// target vault's binding (the ciphertext is cryptographically bound to its vault), so the item gets a
    /// new id there. Returns the item's id after the move.
    /// </summary>
    Task<Guid> MoveItemAsync(Guid userId, Guid itemId, Guid targetVaultId, Guid? targetFolderId, CancellationToken ct = default);

    /// <summary>Moves several items at once (same rules as <see cref="MoveItemAsync"/>), atomically.</summary>
    Task MoveItemsAsync(Guid userId, IReadOnlyList<Guid> itemIds, Guid targetVaultId, Guid? targetFolderId, CancellationToken ct = default);

    /// <summary>
    /// Moves a folder under another parent (null = vault root) — within its vault a plain reparent (a
    /// folder can never be moved into itself or one of its descendants); into ANOTHER vault the whole
    /// subtree moves: folders are recreated there and every contained item is re-encrypted under the
    /// target vault's binding, atomically. Returns the folder's id after the move.
    /// </summary>
    Task<Guid> MoveFolderAsync(Guid userId, Guid folderId, Guid targetVaultId, Guid? targetParentFolderId, CancellationToken ct = default);

    Task<string?> ReadItemAsync(Guid userId, Guid itemId, CancellationToken ct = default);

    /// <summary>Bulk-imports logins (e.g. from a browser password export) into a vault; returns the count.</summary>
    Task<int> ImportLoginsAsync(Guid userId, Guid vaultId, IReadOnlyList<ImportedLogin> logins, CancellationToken ct = default);

    /// <summary>
    /// Exports the vault's LOGIN items decrypted (for an Edge/Chrome-compatible CSV via
    /// <see cref="EdgePasswordCsv.Write"/>). A bulk plaintext disclosure, so: personal vaults only for
    /// their owner; TEAM vaults only for tenant admins (or system admins) — a Manage grant is not enough.
    /// Audited as one export event.
    /// </summary>
    Task<IReadOnlyList<ImportedLogin>> ExportVaultLoginsAsync(Guid userId, Guid vaultId, CancellationToken ct = default);

    /// <summary>
    /// Searches ALL vaults the user can read (personal, or the tenant's shared vaults when
    /// <paramref name="teamVaults"/> is true) for items matching <paramref name="query"/> in any field —
    /// name, and the decrypted content (login URL / username / note, or the value of other item types).
    /// Login passwords are deliberately NOT matched. Queries shorter than 2 characters return nothing.
    /// </summary>
    Task<IReadOnlyList<VaultItemSearchHit>> SearchItemsAsync(Guid userId, Guid tenantId, bool teamVaults, string query, CancellationToken ct = default);
}

/// <summary>A search match across vaults; MatchedField names the field that matched ("Name", "Url",
/// "Username", "Note" or "Value") so the UI can show where the hit was found.</summary>
public sealed record VaultItemSearchHit(Guid VaultId, string VaultName, Guid ItemId, Guid? FolderId, ItemType Type, string Name, string MatchedField);
