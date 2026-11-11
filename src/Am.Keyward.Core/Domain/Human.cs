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

    /// <summary>
    /// Whether AI agent tokens may be allowlisted for this vault and reach it. Off by default; only tenant
    /// vaults can turn it on — a personal vault is never reachable by an agent.
    /// </summary>
    public bool AgentAccessAllowed { get; private set; }

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

    /// <summary>
    /// Opens the vault to AI agent tokens — a team vault (by someone with Manage) or, since decision T12 B, a personal
    /// vault (by its owner, for the owner's own tokens only).
    /// </summary>
    public void AllowAgentAccess() => AgentAccessAllowed = true;

    public void DenyAgentAccess() => AgentAccessAllowed = false;

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

//// <summary>Aggregate root: a typed item in a vault (optionally in a folder), with a version chain.</summary>
public sealed class VaultItem
{
    /// <summary>The longest item name (the column width).</summary>
    public const int MaxNameLength = 256;

    private readonly List<VaultItemVersion> _versions = [];

    public Guid Id { get; private set; }
    public Guid VaultId { get; private set; }

    /// <summary>
    /// Stable, shareable public id for deep links. A random value, unrelated to the crypto-bound
    /// <see cref="Id"/> and NOT part of any AAD — so it survives a cross-vault move (which must mint a new
    /// <see cref="Id"/> because the ciphertext is rebound to the target vault). A documentation link built on
    /// this therefore stays valid across moves; <see cref="AdoptPublicId"/> carries it to the moved item.
    /// </summary>
    public Guid PublicId { get; private set; }

    /// <summary>Denormalized vault isolation keys (drive the query filter + row-level security).</summary>
    public Guid? TenantId { get; private set; }
    public Guid? OwnerUserId { get; private set; }

    public Guid? FolderId { get; private set; }
    public ItemType Type { get; private set; }
    public string Name { get; private set; }
    public Guid? CreatedBy { get; private set; }
    public Guid? CurrentVersionId { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }

    /// <summary>
    /// The item's revision: renewed on EVERY change — a new value, a rename, a folder move. It is the
    /// optimistic-concurrency token and the version callers echo back (the agent API's ETag / If-Match), so a
    /// rename made in between is detected just like a new value. Equals <see cref="CurrentVersionId"/> right after a
    /// new value is stored.
    /// </summary>
    public Guid Revision { get; private set; }

    /// <summary>
    /// The highest version number ever assigned to this item — a persisted counter, so the next number never
    /// depends on how much of the history happens to be loaded (or was pruned).
    /// </summary>
    public int LastVersionNumber { get; private set; }

    /// <summary>
    /// Set while the current name was given by an AI agent token: which token renamed the item, and the name it had
    /// before that agent's first rename. A reveal request shows both, so an agent cannot rename «Prod DB root» to
    /// «wifi guest», ask for the password and rename it back unnoticed. A rename by a person clears both.
    /// </summary>
    public Guid? RenamedByAgentTokenId { get; private set; }

    /// <inheritdoc cref="RenamedByAgentTokenId"/>
    public string? NameBeforeAgentRename { get; private set; }

    public IReadOnlyList<VaultItemVersion> Versions => _versions;

    public VaultItem(Guid id, Guid vaultId, Guid? tenantId, Guid? ownerUserId, Guid? folderId, ItemType type, string name, Guid? createdBy, DateTimeOffset createdAt)
    {
        Id = id;
        VaultId = vaultId;
        PublicId = Guid.NewGuid();
        TenantId = tenantId;
        OwnerUserId = ownerUserId;
        FolderId = folderId;
        Type = type;
        Name = ValidName(name);
        CreatedBy = createdBy;
        CreatedAt = createdAt;
        Revision = Guid.NewGuid();
    }

    /// <summary>
    /// Adopts another item's stable <see cref="PublicId"/>. Used only when a cross-vault move recreates this
    /// item under a new <see cref="Id"/> (its ciphertext is rebound to the target vault) so the shareable
    /// deep link survives the move.
    /// </summary>
    public void AdoptPublicId(Guid publicId) => PublicId = publicId;

    /// <summary>
    /// Takes over what must survive a cross-vault move besides the content: the stable <see cref="PublicId"/> and an
    /// agent rename marker (<see cref="RenamedByAgentTokenId"/>, <see cref="NameBeforeAgentRename"/>) — otherwise a
    /// move would launder an agent's rename before a reveal request.
    /// </summary>
    public void AdoptLineageOf(VaultItem source)
    {
        ArgumentNullException.ThrowIfNull(source);
        PublicId = source.PublicId;
        RenamedByAgentTokenId = source.RenamedByAgentTokenId;
        NameBeforeAgentRename = source.NameBeforeAgentRename;
    }

    /// <summary>Stores a new value as the current version, numbered after the highest number ever assigned.</summary>
    public VaultItemVersion AddVersion(Guid versionId, EncryptedValue encrypted, DateTimeOffset at)
    {
        var version = new VaultItemVersion(versionId, Id, TenantId, OwnerUserId, ++LastVersionNumber, encrypted, at);
        _versions.Add(version);
        CurrentVersionId = version.Id;
        Revision = version.Id;
        return version;
    }

    /// <summary>
    /// Carries one version of another item's history over, keeping its number and time — used when a cross-vault
    /// move recreates the item (each version re-encrypted under the target's binding). <paramref name="isCurrent"/>
    /// marks the version that becomes <see cref="CurrentVersionId"/>.
    /// </summary>
    public VaultItemVersion CarryOverVersion(Guid versionId, int versionNumber, EncryptedValue encrypted, DateTimeOffset createdAt, bool isCurrent)
    {
        if (versionNumber < 1 || _versions.Any(v => v.VersionNumber == versionNumber))
        {
            throw new ArgumentOutOfRangeException(nameof(versionNumber), "Each carried-over version needs its own positive number.");
        }

        var version = new VaultItemVersion(versionId, Id, TenantId, OwnerUserId, versionNumber, encrypted, createdAt);
        _versions.Add(version);
        LastVersionNumber = Math.Max(LastVersionNumber, versionNumber);
        if (isCurrent)
        {
            CurrentVersionId = version.Id;
            Revision = version.Id;
        }

        return version;
    }

    /// <summary>
    /// Renames the item. <paramref name="agentTokenId"/> is the AI agent token doing it (null for a person): the
    /// item then remembers the name it had before that agent's rename (see <see cref="RenamedByAgentTokenId"/>).
    /// Returns whether the name actually changed.
    /// </summary>
    public bool Rename(string name, Guid? agentTokenId = null)
    {
        var trimmed = ValidName(name);
        if (string.Equals(trimmed, Name, StringComparison.Ordinal))
        {
            return false;
        }

        if (agentTokenId is { } tokenId)
        {
            // Keep the earliest name no agent chose: a chain of agent renames still shows what a person last named it.
            NameBeforeAgentRename ??= Name;
            RenamedByAgentTokenId = tokenId;
        }
        else
        {
            RenamedByAgentTokenId = null;
            NameBeforeAgentRename = null;
        }

        Name = trimmed;
        Revision = Guid.NewGuid();
        return true;
    }

    /// <summary>Reparent within the same vault (null = vault root). Cross-vault moves are not allowed.</summary>
    public void MoveToFolder(Guid? folderId)
    {
        if (FolderId == folderId)
        {
            return;
        }

        FolderId = folderId;
        Revision = Guid.NewGuid();
    }

    /// <summary>The current version. Only the current version needs to be loaded for this.</summary>
    public VaultItemVersion Current =>
        _versions.SingleOrDefault(v => v.Id == CurrentVersionId)
        ?? throw new InvalidOperationException("Vault item has no current version.");

    private static string ValidName(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            throw new ArgumentException("Item name required.", nameof(name));
        }

        var trimmed = name.Trim();
        if (trimmed.Length > MaxNameLength)
        {
            throw new ArgumentException($"An item name may be at most {MaxNameLength} characters.", nameof(name));
        }

        return trimmed;
    }
}

// <summary>An immutable, encrypted version of a vault item.</summary>
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
