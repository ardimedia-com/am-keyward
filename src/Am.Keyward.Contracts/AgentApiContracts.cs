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

/// <summary>
/// Creates an item (<c>POST /vaults/{id}/items</c>). A Login takes <see cref="Url"/>, <see cref="Username"/>,
/// <see cref="Password"/> and <see cref="Note"/>; every other type takes <see cref="Value"/>. The value is never
/// echoed back.
/// </summary>
public sealed record AgentCreateItemRequest(
    string Type,
    string Name,
    Guid? FolderId = null,
    string? Url = null,
    string? Username = null,
    string? Password = null,
    string? Note = null,
    string? Value = null);

/// <summary>
/// Changes an item (<c>PATCH /items/{id}</c>, with <c>If-Match: "&lt;versionId&gt;"</c>). Omitted fields stay as
/// they are; a Login changes field by field, every other type by its whole <see cref="Value"/>.
/// </summary>
public sealed record AgentUpdateItemRequest(
    string? Name = null,
    string? Url = null,
    string? Username = null,
    string? Password = null,
    string? Note = null,
    string? Value = null);

/// <summary>Result of a create or update: the item, its deep link and its new version (also the ETag).</summary>
public sealed record AgentItemWrittenResponse(Guid Id, string Link, Guid VersionId);

/// <summary>
/// Asks to see one secret field (<c>POST /items/{id}/reveal-requests</c>): <c>"Password"</c> or <c>"Note"</c> of a
/// Login, <c>"Value"</c> of any other type. The reason is shown to the human who decides.
/// </summary>
public sealed record AgentRevealRequestBody(string Field, string Reason);

/// <summary>
/// Where a reveal request stands: <c>Pending</c> (waiting for the human, until <see cref="ExpiresAt"/>),
/// <c>Approved</c> (fetch it once via <c>POST /reveal-requests/{id}/consume</c> before <see cref="ConsumeBy"/>),
/// <c>Rejected</c>, <c>Expired</c> or <c>Consumed</c>. <see cref="ItemLink"/> opens the entry in the KEYWARD UI, where the
/// person can copy the value themselves — often simpler than a reveal.
/// </summary>
public sealed record AgentRevealStateResponse(
    Guid Id, Guid ItemId, string Field, string Status, DateTimeOffset ExpiresAt, DateTimeOffset? ConsumeBy, string ItemLink);

/// <summary>The revealed value — returned exactly once, never cached.</summary>
public sealed record AgentRevealValueResponse(Guid RequestId, Guid ItemId, string Field, string Value);

/// <summary>
/// What <c>GET /token</c> tells an assistant about the token it holds: its permissions (scope names), how many vaults
/// and applications it reaches, and whether it may create applications. For <c>amkeyward-mcp check</c>.
/// </summary>
public sealed record AgentTokenInfoResponse(
    Guid Id,
    string Name,
    IReadOnlyList<string> Permissions,
    int VaultCount,
    int ApplicationCount,
    bool MayCreateApplications,
    string AllowedNetworks,
    DateTimeOffset ExpiresAt);

/// <summary>
/// An application as the agent API shows it (<c>GET /applications</c>): environments and keys, and per environment
/// only whether a value is set. <see cref="Link"/> opens it in the Keyward UI (where a person pastes values);
/// <see cref="TokensLink"/> is where a person issues the app token — agents cannot.
/// </summary>
public sealed record AgentApplicationResponse(
    Guid Id,
    string Name,
    bool CreatedByThisToken,
    IReadOnlyList<string> Environments,
    IReadOnlyList<AgentSecretKeyResponse> Keys,
    string Link,
    string TokensLink);

/// <summary>One key; <see cref="CreatedByThisToken"/> keys may be renamed or deleted by the token while they hold no value.</summary>
public sealed record AgentSecretKeyResponse(string Key, bool CreatedByThisToken, IReadOnlyList<AgentSecretValueStateResponse> Values);

/// <summary>
/// Whether <see cref="Environment"/> holds a value for the key. <see cref="VersionId"/> is the ETag to send as
/// <c>If-Match</c> when replacing it; without a value, send <c>If-None-Match: *</c>. The value itself is never returned.
/// </summary>
public sealed record AgentSecretValueStateResponse(string Environment, bool ValueSet, Guid? VersionId, DateTimeOffset? RotateBy = null, string RotationNote = "");

/// <summary>
/// Moves an entry (<c>POST /items/{id}/move</c>) into another folder and/or another reachable vault; the token needs
/// «Create and update entries» and the user Write on both vaults. Across vaults the entry gets a new id; its link
/// stays the same.
/// </summary>
public sealed record AgentMoveItemRequest(Guid VaultId, Guid? FolderId = null);

/// <summary>
/// One app token of an application (<c>GET /applications/{id}/tokens</c>): metadata only — never the token or its
/// prefix. <see cref="Status"/> is Pending (no value issued yet), Active, Expired or Revoked.
/// </summary>
public sealed record AgentClientTokenResponse(
    Guid Id,
    string Name,
    string Environment,
    string Status,
    string Note,
    DateTimeOffset CreatedAt,
    DateTimeOffset? ExpiresAt,
    DateTimeOffset? LastAccessAt,
    string? LastAccessIp,
    AgentTokenMonitorResponse? Monitor);

/// <summary>Heartbeat monitoring of an app token: whether it is on, its state (Unknown, Up, Down, Snoozed) and the next deadline.</summary>
public sealed record AgentTokenMonitorResponse(bool Enabled, string State, int MaxSilenceMinutes, DateTimeOffset? NextDeadline, DateTimeOffset? LastStateChangeAt);

/// <summary>App-token access statistics of an application (<c>GET /applications/{id}/statistics?days=30</c>).</summary>
public sealed record AgentApplicationStatisticsResponse(
    IReadOnlyList<AgentDailyAccessResponse> Daily,
    IReadOnlyList<AgentAccessAddressResponse> Addresses,
    IReadOnlyList<AgentAccessAlertResponse> Alerts);

public sealed record AgentDailyAccessResponse(Guid TokenId, DateOnly Date, long Requests);

public sealed record AgentAccessAddressResponse(Guid TokenId, string IpAddress, DateTimeOffset FirstSeenAt, DateTimeOffset LastSeenAt);

public sealed record AgentAccessAlertResponse(Guid TokenId, string Kind, string? IpAddress, DateTimeOffset CreatedAt);

/// <summary>Creates an application (<c>POST /applications</c>). It starts with the tenant's default environments; others listed here are added.</summary>
public sealed record AgentCreateApplicationRequest(string Name, IReadOnlyList<string>? Environments = null);

/// <summary>Renames an application the token created (<c>PATCH /applications/{id}</c>).</summary>
public sealed record AgentRenameApplicationRequest(string Name);

/// <summary>Adds an environment (<c>POST /applications/{id}/environments</c>).</summary>
public sealed record AgentAddEnvironmentRequest(string Name);

/// <summary>
/// Creates a key (<c>POST /applications/{id}/secrets</c>). Without <see cref="Value"/> it is a placeholder («not
/// set») for a person to fill; with one, <see cref="Environment"/> is required. The value is never echoed.
/// </summary>
public sealed record AgentCreateSecretRequest(string Key, string? Environment = null, string? Value = null);

/// <summary>Sets a key's value in one environment (<c>PUT /applications/{id}/secrets/{key}</c>, with If-Match or If-None-Match: *).</summary>
public sealed record AgentSetSecretValueRequest(string Environment, string Value);

/// <summary>Renames a key the token created and that holds no value (<c>PATCH /applications/{id}/secrets/{key}</c>).</summary>
public sealed record AgentRenameSecretRequest(string Key);

/// <summary>Result of creating a key or setting a value: never the value, only whether one is set, its version (also the ETag) and the UI link.</summary>
public sealed record AgentSecretWrittenResponse(Guid ApplicationId, string Key, string? Environment, bool ValueSet, Guid? VersionId, string Link);
