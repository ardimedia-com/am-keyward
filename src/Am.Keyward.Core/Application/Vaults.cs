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

/// <summary>An existing share on a vault.</summary>
public sealed record VaultShare(Guid GranteeUserId, string DisplayName, Permission Permission);

/// <summary>Adds a folder to a vault the user owns.</summary>
public sealed record AddVaultFolderCommand(Guid UserId, Guid VaultId, string Name);

/// <summary>Adds a typed item to a vault, encrypting its content into a new version.</summary>
public sealed record AddVaultItemCommand(Guid UserId, Guid VaultId, Guid? FolderId, ItemType Type, string Name, string Content);

/// <summary>Updates an item's name/folder and stores its new content as a new encrypted version.</summary>
public sealed record UpdateVaultItemCommand(Guid UserId, Guid ItemId, string Name, Guid? FolderId, string Content);

public sealed record VaultSummary(Guid Id, string Name, ProtectionMode ProtectionMode, DateTimeOffset CreatedAt);

public sealed record VaultItemSummary(Guid Id, Guid? FolderId, ItemType Type, string Name, DateTimeOffset CreatedAt);

/// <summary>An item plus its decrypted content (for viewing/editing).</summary>
public sealed record VaultItemDetail(Guid Id, Guid VaultId, Guid? FolderId, ItemType Type, string Name, string Content);

public sealed record VaultFolderSummary(Guid Id, string Name, DateTimeOffset CreatedAt);

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

    Task<string?> ReadItemAsync(Guid userId, Guid itemId, CancellationToken ct = default);

    /// <summary>Bulk-imports logins (e.g. from a browser password export) into a vault; returns the count.</summary>
    Task<int> ImportLoginsAsync(Guid userId, Guid vaultId, IReadOnlyList<ImportedLogin> logins, CancellationToken ct = default);
}
