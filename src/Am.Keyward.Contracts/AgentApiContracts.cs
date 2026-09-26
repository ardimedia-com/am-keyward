namespace Am.Keyward.Contracts;

// Wire shapes of the agent API (GET/POST /keyward/api/v1/agent/...). Item types travel as their name
// ("Login", "SecureNote", "ApiCredential", "ConnectionString", "Generic"). No shape ever carries a secret value.

/// <summary>A vault the agent token may reach.</summary>
public sealed record AgentVaultResponse(Guid Id, string Name);

/// <summary>A vault's structure: its folders and the names/types of its items.</summary>
public sealed record AgentVaultTreeResponse(Guid VaultId, string VaultName, IReadOnlyList<AgentFolderResponse> Folders, IReadOnlyList<AgentItemSummaryResponse> Items);

public sealed record AgentFolderResponse(Guid Id, string Name, Guid? ParentFolderId);

public sealed record AgentItemSummaryResponse(Guid Id, Guid VaultId, Guid? FolderId, string Type, string Name);

/// <summary>
/// One item without its secret. <see cref="Link"/> is the path of the item's shareable deep link on the Keyward
/// host (relative, e.g. <c>/amkeyward/e/3kTMd9…</c>). <see cref="VersionId"/> is also sent as the ETag.
/// <see cref="Url"/> and <see cref="Username"/> are set for a Login only.
/// </summary>
public sealed record AgentItemResponse(
    Guid Id, Guid VaultId, Guid? FolderId, string Type, string Name, string Link, Guid VersionId, string? Url, string? Username);
