using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Agent;

namespace Am.Keyward.Core.Application;

/// <summary>
/// The batched form of <see cref="IAgentVaultAccess.IsVaultAllowedAsync"/>: the same decision for many vaults in a
/// fixed number of queries (listing and searching otherwise cost one context and several queries per vault).
/// Implemented by the same class as <see cref="IAgentVaultAccess"/>.
/// </summary>
public interface IAgentVaultFilter
{
    /// <summary>The subset of <paramref name="vaultIds"/> the token may reach with <paramref name="scope"/> and <paramref name="permission"/>.</summary>
    Task<IReadOnlySet<Guid>> FilterAllowedVaultsAsync(
        Guid tokenId, IReadOnlyCollection<Guid> vaultIds, AgentScopes scope, Permission permission, CancellationToken ct = default);
}
