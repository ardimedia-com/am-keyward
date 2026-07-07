namespace Am.Keyward.Core.Application;

/// <summary>Stores (creates or versions) a software secret's value for one project environment.</summary>
public sealed record StoreSoftwareSecretCommand(
    Guid TenantId,
    Guid ProjectId,
    string Environment,
    string Key,
    string Value,
    Guid? ActorUserId);

/// <summary>Reads the current value of a software secret for one project environment.</summary>
public sealed record ReadSoftwareSecretQuery(
    Guid TenantId,
    Guid ProjectId,
    string Environment,
    string Key,
    Guid? ActorUserId);

/// <summary>A software secret (one key in a project) and which environments currently hold a value.</summary>
public sealed record SoftwareSecretSummary(string Key, IReadOnlyList<string> EnvironmentsWithValue);

/// <summary>One project environment (id + display name).</summary>
public sealed record EnvironmentInfo(Guid Id, string Name);

/// <summary>One environment's current value for a secret (Value is null when that environment has none).</summary>
public sealed record SecretEnvironmentValue(string Environment, bool HasValue, string? Value);

/// <summary>A secret with its current value in every project environment (for the management view).</summary>
public sealed record SoftwareSecretDetail(string Key, IReadOnlyList<SecretEnvironmentValue> Environments);

/// <summary>Application service for the software-credentials use case (encrypt-and-store / read-and-decrypt).</summary>
public interface ISoftwareSecretService
{
    Task StoreAsync(StoreSoftwareSecretCommand command, CancellationToken ct = default);

    Task<string?> ReadAsync(ReadSoftwareSecretQuery query, CancellationToken ct = default);

    /// <summary>Lists the secrets (keys) in a project and which environments hold a value.</summary>
    Task<IReadOnlyList<SoftwareSecretSummary>> ListSecretsAsync(Guid tenantId, Guid projectId, CancellationToken ct = default);

    /// <summary>One secret with its decrypted value in every project environment (null if the key is absent).</summary>
    Task<SoftwareSecretDetail?> GetSecretAsync(Guid tenantId, Guid projectId, string key, CancellationToken ct = default);

    /// <summary>The project's environments, sorted by name.</summary>
    Task<IReadOnlyList<EnvironmentInfo>> ListEnvironmentsAsync(Guid tenantId, Guid projectId, CancellationToken ct = default);

    /// <summary>
    /// Adds an environment to the project. Like every environment mutation, this is for tenant admins /
    /// system admins only — it changes what every secret and client token of the project offers.
    /// </summary>
    Task AddEnvironmentAsync(Guid tenantId, Guid projectId, string name, Guid? actorUserId, CancellationToken ct = default);

    /// <summary>Renames an environment; values and tokens follow automatically (they bind by id).</summary>
    Task RenameEnvironmentAsync(Guid tenantId, Guid projectId, Guid environmentId, string newName, Guid? actorUserId, CancellationToken ct = default);

    /// <summary>
    /// Deletes an environment: its secret VALUES are deleted and client tokens scoped to it are REVOKED.
    /// The project's last environment cannot be deleted.
    /// </summary>
    Task DeleteEnvironmentAsync(Guid tenantId, Guid projectId, Guid environmentId, Guid? actorUserId, CancellationToken ct = default);

    /// <summary>Deletes a secret (its values in all environments) by key.</summary>
    Task DeleteSecretAsync(Guid tenantId, Guid projectId, string key, Guid? actorUserId, CancellationToken ct = default);
}
