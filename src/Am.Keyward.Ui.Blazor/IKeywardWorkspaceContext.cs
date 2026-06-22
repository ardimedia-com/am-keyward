namespace Am.Keyward.Ui.Blazor;

/// <summary>
/// The active workspace the embedded Keyward UI operates in: the tenant whose organization-owned resources
/// are shown, and the software-credentials project. The <b>host</b> supplies this from its own tenant /
/// project selection (so a host can scope the embedded pages to whatever the signed-in user picked); the
/// standalone reference shell returns its seeded demo tenant/project. The current user/actor and the
/// personal (tenant-less) scope come from <c>ICurrentUser</c> instead, so this only carries the org context.
/// </summary>
public interface IKeywardWorkspaceContext
{
    /// <summary>The active tenant (organization) whose team vaults / software credentials are shown.</summary>
    Guid TenantId { get; }

    /// <summary>The software-credentials project the secrets and client-token pages operate on.</summary>
    Guid ProjectId { get; }
}
