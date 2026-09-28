namespace Am.Keyward.Core.Application;

/// <summary>
/// An application as an agent sees it: its environments and keys, and per environment only whether a value is set
/// and at which version. Never a value, not even part of one.
/// </summary>
public sealed record AgentApplicationView(
    Guid Id,
    string Name,
    bool CreatedByThisToken,
    IReadOnlyList<string> Environments,
    IReadOnlyList<AgentSecretKeyView> Keys);

/// <summary>One key of an application; <see cref="CreatedByThisToken"/> tells whether the token may rename or delete it (while empty).</summary>
public sealed record AgentSecretKeyView(string Key, bool CreatedByThisToken, IReadOnlyList<AgentSecretValueState> Values);

/// <summary>Whether an environment holds a value for a key; <see cref="VersionId"/> is the ETag for the next write.</summary>
public sealed record AgentSecretValueState(string Environment, bool ValueSet, Guid? VersionId);

/// <summary>The token may not manage applications at all: permission not granted, token no longer valid, or its user may no longer manage the software side.</summary>
public sealed class AgentApplicationsNotPermittedException()
    : UnauthorizedAccessException("This agent token may not manage applications.");

/// <summary>
/// The application, key or environment is out of the token's reach — or does not exist; the two are
/// deliberately indistinguishable.
/// </summary>
public sealed class AgentApplicationNotFoundException()
    : KeyNotFoundException("Not found.");

/// <summary>
/// The name, key or environment already exists. Carries a message the agent can act on.
/// </summary>
public sealed class AgentApplicationConflictException(string message) : InvalidOperationException(message);

/// <summary>
/// The change is within reach but reserved to a person: renaming or deleting what the token did not create, or what
/// already holds a value or an issued app token.
/// </summary>
public sealed class AgentApplicationChangeRefusedException(string message) : UnauthorizedAccessException(message);

/// <summary>
/// Application management for agent tokens (<see cref="Domain.Agent.AgentScopes.ManageApplications"/>). Runs in
/// the token's tenant and user scope, as the agent authentication handler sets it, and delegates every change to
/// the same project and secret services the UI uses — so names, keys and environments are validated by exactly
/// one rule set, and every change is audited as the agent. Values go in, never out.
/// <para>
/// Reach: the token's allowlisted applications plus those it created; anything else behaves as missing
/// (<see cref="AgentApplicationNotFoundException"/>). App tokens are out of scope entirely.
/// </para>
/// </summary>
public interface IAgentApplicationService
{
    /// <summary>The reachable applications. Throws <see cref="AgentApplicationsNotPermittedException"/> without the permission.</summary>
    Task<IReadOnlyList<AgentApplicationView>> ListAsync(Guid tokenId, CancellationToken ct = default);

    Task<AgentApplicationView> GetAsync(Guid tokenId, Guid applicationId, CancellationToken ct = default);

    /// <summary>
    /// Creates an application (needs «may create new applications»). It starts with the tenant's default
    /// environments; <paramref name="environments"/> not among them are added.
    /// </summary>
    Task<Guid> CreateAsync(Guid tokenId, string name, IReadOnlyList<string> environments, CancellationToken ct = default);

    Task AddEnvironmentAsync(Guid tokenId, Guid applicationId, string environment, CancellationToken ct = default);

    /// <summary>
    /// Creates a key. Without a value it is a placeholder («not set») for a person to fill; with one, the value is
    /// stored for <paramref name="environment"/> and its version returned.
    /// </summary>
    Task<StoredSecretValue?> CreateSecretAsync(
        Guid tokenId, Guid applicationId, string key, string? environment, string? value, CancellationToken ct = default);

    /// <summary>Sets a value while it is still at <paramref name="precondition"/> (see <see cref="SecretValuePrecondition"/>).</summary>
    Task<StoredSecretValue> SetSecretValueAsync(
        Guid tokenId, Guid applicationId, string key, string environment, string value, SecretValuePrecondition precondition,
        CancellationToken ct = default);

    /// <summary>Renames a key this token created and that holds no value in any environment.</summary>
    Task RenameSecretAsync(Guid tokenId, Guid applicationId, string key, string newKey, CancellationToken ct = default);

    /// <summary>Deletes a key this token created and that holds no value in any environment.</summary>
    Task DeleteSecretAsync(Guid tokenId, Guid applicationId, string key, CancellationToken ct = default);

    /// <summary>Renames an application this token created that holds no value, no key of someone else and no issued app token.</summary>
    Task RenameAsync(Guid tokenId, Guid applicationId, string name, CancellationToken ct = default);

    /// <summary>Deletes an application under the same condition as <see cref="RenameAsync"/>.</summary>
    Task DeleteAsync(Guid tokenId, Guid applicationId, CancellationToken ct = default);
}
