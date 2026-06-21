using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.ValueObjects;

namespace Am.Keyward.Core.Domain.Human;

/// <summary>
/// Aggregate root for human credentials. Owned by a Tenant, Group, or User. A personal vault is
/// owned by a User and is tenant-less (<see cref="TenantId"/> = null). Carries the per-vault
/// <see cref="ProtectionMode"/>. Contains its (flat, v0.1) <see cref="Folder"/>s.
/// </summary>
public sealed class Vault
{
    private readonly List<Folder> _folders = [];

    public Guid Id { get; }

    /// <summary>Null = tenant-less personal vault (must then be User-owned).</summary>
    public Guid? TenantId { get; }

    public OwnerType OwnerType { get; }
    public Guid OwnerId { get; }
    public ProtectionMode ProtectionMode { get; }
    public string Name { get; private set; }
    public DateTimeOffset CreatedAt { get; }
    public IReadOnlyList<Folder> Folders => _folders;

    public Vault(Guid id, Guid? tenantId, OwnerType ownerType, Guid ownerId, ProtectionMode protectionMode, string name, DateTimeOffset createdAt)
    {
        if (ownerType == OwnerType.User && tenantId is not null)
        {
            throw new ArgumentException("A personal (User-owned) vault is tenant-less; TenantId must be null.", nameof(tenantId));
        }

        if (ownerType != OwnerType.User && tenantId is null)
        {
            throw new ArgumentException("A Tenant/Group-owned vault must have a TenantId.", nameof(tenantId));
        }

        if (string.IsNullOrWhiteSpace(name))
        {
            throw new ArgumentException("Vault name required.", nameof(name));
        }

        Id = id;
        TenantId = tenantId;
        OwnerType = ownerType;
        OwnerId = ownerId;
        ProtectionMode = protectionMode;
        Name = name.Trim();
        CreatedAt = createdAt;
    }

    public Folder AddFolder(Guid id, string name, DateTimeOffset createdAt)
    {
        var folder = new Folder(id, Id, name, createdAt);
        _folders.Add(folder);
        return folder;
    }
}

/// <summary>Belongs to exactly one vault and inherits its tenant/owner/protection. Flat (no nesting) in v0.1.</summary>
public sealed class Folder
{
    public Guid Id { get; }
    public Guid VaultId { get; }
    public string Name { get; private set; }
    public DateTimeOffset CreatedAt { get; }

    public Folder(Guid id, Guid vaultId, string name, DateTimeOffset createdAt)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            throw new ArgumentException("Folder name required.", nameof(name));
        }

        Id = id;
        VaultId = vaultId;
        Name = name.Trim();
        CreatedAt = createdAt;
    }

    public void Rename(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            throw new ArgumentException("Folder name required.", nameof(name));
        }

        Name = name.Trim();
    }
}

/// <summary>Aggregate root: a typed item in a vault (optionally in a folder), with a version chain.</summary>
public sealed class VaultItem
{
    private readonly List<VaultItemVersion> _versions = [];

    public Guid Id { get; }
    public Guid VaultId { get; }
    public Guid? FolderId { get; private set; }
    public ItemType Type { get; }
    public string Name { get; private set; }
    public Guid? CreatedBy { get; }
    public Guid? CurrentVersionId { get; private set; }
    public DateTimeOffset CreatedAt { get; }
    public IReadOnlyList<VaultItemVersion> Versions => _versions;

    public VaultItem(Guid id, Guid vaultId, Guid? folderId, ItemType type, string name, Guid? createdBy, DateTimeOffset createdAt)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            throw new ArgumentException("Item name required.", nameof(name));
        }

        Id = id;
        VaultId = vaultId;
        FolderId = folderId;
        Type = type;
        Name = name.Trim();
        CreatedBy = createdBy;
        CreatedAt = createdAt;
    }

    public VaultItemVersion AddVersion(Guid versionId, EncryptedValue encrypted, DateTimeOffset at)
    {
        var version = new VaultItemVersion(versionId, Id, _versions.Count + 1, encrypted, at);
        _versions.Add(version);
        CurrentVersionId = version.Id;
        return version;
    }

    /// <summary>Reparent within the same vault (null = vault root). Cross-vault moves are not allowed.</summary>
    public void MoveToFolder(Guid? folderId) => FolderId = folderId;

    public VaultItemVersion Current =>
        _versions.SingleOrDefault(v => v.Id == CurrentVersionId)
        ?? throw new InvalidOperationException("Vault item has no current version.");
}

/// <summary>An immutable, encrypted version of a vault item.</summary>
public sealed class VaultItemVersion
{
    public Guid Id { get; }
    public Guid VaultItemId { get; }
    public int VersionNumber { get; }
    public EncryptedValue Encrypted { get; }
    public DateTimeOffset CreatedAt { get; }

    public VaultItemVersion(Guid id, Guid vaultItemId, int versionNumber, EncryptedValue encrypted, DateTimeOffset createdAt)
    {
        Id = id;
        VaultItemId = vaultItemId;
        VersionNumber = versionNumber;
        Encrypted = encrypted;
        CreatedAt = createdAt;
    }
}
