using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.ValueObjects;

namespace Am.Keyward.Core.Domain.Human;

/// <summary>
/// Aggregate root for human credentials. Owned by a Tenant, Group, or User. A personal vault is
/// owned by a User and is tenant-less (<see cref="TenantId"/> = null). Carries the per-vault
/// <see cref="ProtectionMode"/>. Contains its (flat, v0.1) <see cref="Folder"/>s.
/// Isolation: tenant vaults are scoped by <see cref="TenantId"/>; personal vaults by
/// <see cref="OwnerUserId"/> (set only when User-owned). Both are denormalized onto every child so the
/// query filter and SQL Server row-level security can decide per row.
/// </summary>
public sealed class Vault
{
    private readonly List<Folder> _folders = [];

    public Guid Id { get; private set; }

    /// <summary>Null = tenant-less personal vault (must then be User-owned).</summary>
    public Guid? TenantId { get; private set; }

    public OwnerType OwnerType { get; private set; }
    public Guid OwnerId { get; private set; }

    /// <summary>The owning user for a personal (User-owned) vault; null for Tenant/Group vaults.</summary>
    public Guid? OwnerUserId { get; private set; }

    public ProtectionMode ProtectionMode { get; private set; }
    public string Name { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }
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
        OwnerUserId = ownerType == OwnerType.User ? ownerId : null;
        ProtectionMode = protectionMode;
        Name = name.Trim();
        CreatedAt = createdAt;
    }

    public Folder AddFolder(Guid id, string name, DateTimeOffset createdAt, Guid? parentFolderId = null)
    {
        var folder = new Folder(id, Id, TenantId, OwnerUserId, name, createdAt, parentFolderId);
        _folders.Add(folder);
        return folder;
    }

    public void Rename(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            throw new ArgumentException("Vault name required.", nameof(name));
        }

        Name = name.Trim();
    }
}

/// <summary>Belongs to exactly one vault and inherits its tenant/owner/protection. Flat (no nesting) in v0.1.</summary>
public sealed class Folder
{
    public Guid Id { get; private set; }
    public Guid VaultId { get; private set; }

    /// <summary>Denormalized vault isolation keys (drive the query filter + row-level security).</summary>
    public Guid? TenantId { get; private set; }
    public Guid? OwnerUserId { get; private set; }

    /// <summary>Optional parent folder (same vault) — folders form a tree; null = vault root.</summary>
    public Guid? ParentFolderId { get; private set; }

    public string Name { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }

    public Folder(Guid id, Guid vaultId, Guid? tenantId, Guid? ownerUserId, string name, DateTimeOffset createdAt, Guid? parentFolderId = null)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            throw new ArgumentException("Folder name required.", nameof(name));
        }

        Id = id;
        VaultId = vaultId;
        TenantId = tenantId;
        OwnerUserId = ownerUserId;
        ParentFolderId = parentFolderId;
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

    /// <summary>Reparents the folder within its vault (null = vault root). Cycle checks are the service's job.</summary>
    public void MoveTo(Guid? parentFolderId) => ParentFolderId = parentFolderId;
}

/// <summary>Aggregate root: a typed item in a vault (optionally in a folder), with a version chain.</summary>
public sealed class VaultItem
{
    private readonly List<VaultItemVersion> _versions = [];

    public Guid Id { get; private set; }
    public Guid VaultId { get; private set; }

    /// <summary>Denormalized vault isolation keys (drive the query filter + row-level security).</summary>
    public Guid? TenantId { get; private set; }
    public Guid? OwnerUserId { get; private set; }

    public Guid? FolderId { get; private set; }
    public ItemType Type { get; private set; }
    public string Name { get; private set; }
    public Guid? CreatedBy { get; private set; }
    public Guid? CurrentVersionId { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }
    public IReadOnlyList<VaultItemVersion> Versions => _versions;

    public VaultItem(Guid id, Guid vaultId, Guid? tenantId, Guid? ownerUserId, Guid? folderId, ItemType type, string name, Guid? createdBy, DateTimeOffset createdAt)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            throw new ArgumentException("Item name required.", nameof(name));
        }

        Id = id;
        VaultId = vaultId;
        TenantId = tenantId;
        OwnerUserId = ownerUserId;
        FolderId = folderId;
        Type = type;
        Name = name.Trim();
        CreatedBy = createdBy;
        CreatedAt = createdAt;
    }

    public VaultItemVersion AddVersion(Guid versionId, EncryptedValue encrypted, DateTimeOffset at)
    {
        var version = new VaultItemVersion(versionId, Id, TenantId, OwnerUserId, _versions.Count + 1, encrypted, at);
        _versions.Add(version);
        CurrentVersionId = version.Id;
        return version;
    }

    public void Rename(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            throw new ArgumentException("Item name required.", nameof(name));
        }

        Name = name.Trim();
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
    public Guid Id { get; private set; }
    public Guid VaultItemId { get; private set; }

    /// <summary>Denormalized vault isolation keys (drive the query filter + row-level security).</summary>
    public Guid? TenantId { get; private set; }
    public Guid? OwnerUserId { get; private set; }

    public int VersionNumber { get; private set; }
    public EncryptedValue Encrypted { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }

    public VaultItemVersion(Guid id, Guid vaultItemId, Guid? tenantId, Guid? ownerUserId, int versionNumber, EncryptedValue encrypted, DateTimeOffset createdAt)
    {
        Id = id;
        VaultItemId = vaultItemId;
        TenantId = tenantId;
        OwnerUserId = ownerUserId;
        VersionNumber = versionNumber;
        Encrypted = encrypted;
        CreatedAt = createdAt;
    }
}
