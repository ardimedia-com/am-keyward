using Am.Keyward.Core.Domain;

namespace Am.Keyward.Core.Application;

/// <summary>Creates a personal (tenant-less, user-owned) vault.</summary>
public sealed record CreatePersonalVaultCommand(Guid UserId, string Name);

/// <summary>Adds a folder to a vault the user owns.</summary>
public sealed record AddVaultFolderCommand(Guid UserId, Guid VaultId, string Name);

/// <summary>Adds a typed item to a vault, encrypting its content into a new version.</summary>
public sealed record AddVaultItemCommand(Guid UserId, Guid VaultId, Guid? FolderId, ItemType Type, string Name, string Content);

public sealed record VaultSummary(Guid Id, string Name, ProtectionMode ProtectionMode, DateTimeOffset CreatedAt);

public sealed record VaultItemSummary(Guid Id, Guid? FolderId, ItemType Type, string Name, DateTimeOffset CreatedAt);

public sealed record VaultFolderSummary(Guid Id, string Name, DateTimeOffset CreatedAt);

/// <summary>
/// Application service for human vaults. v0.1 scope: personal (user-owned, server-side encrypted) vaults
/// — create vault/folder/item, read an item, list. Tenant/group vaults and grant-based sharing layer on
/// next. Access is server-authoritative on the current user.
/// </summary>
public interface IVaultService
{
    Task<Guid> CreatePersonalVaultAsync(CreatePersonalVaultCommand command, CancellationToken ct = default);

    Task<Guid> AddFolderAsync(AddVaultFolderCommand command, CancellationToken ct = default);

    Task<Guid> AddItemAsync(AddVaultItemCommand command, CancellationToken ct = default);

    Task<string?> ReadItemAsync(Guid userId, Guid itemId, CancellationToken ct = default);

    Task<IReadOnlyList<VaultSummary>> ListVaultsAsync(Guid userId, CancellationToken ct = default);

    Task<IReadOnlyList<VaultFolderSummary>> ListFoldersAsync(Guid userId, Guid vaultId, CancellationToken ct = default);

    Task<IReadOnlyList<VaultItemSummary>> ListItemsAsync(Guid userId, Guid vaultId, CancellationToken ct = default);
}
