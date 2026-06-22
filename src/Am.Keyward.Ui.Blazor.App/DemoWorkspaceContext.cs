using Am.Keyward.Ui.Blazor;

namespace Am.Keyward.Ui.Blazor.App;

/// <summary>
/// Reference-shell implementation of <see cref="IKeywardWorkspaceContext"/>: the embedded UI operates in
/// the seeded demo tenant/project. A real host implements this from its own tenant/project selection (e.g.
/// the active tenant from membership and the project the user picked) so the same RCL pages scope to the
/// host's context.
/// </summary>
public sealed class DemoWorkspaceContext : IKeywardWorkspaceContext
{
    public Guid TenantId => Demo.TenantId;

    public Guid ProjectId => Demo.ProjectId;
}
