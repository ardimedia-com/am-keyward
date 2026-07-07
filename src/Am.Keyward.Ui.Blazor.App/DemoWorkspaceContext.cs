using Am.Keyward.Ui.Blazor;

namespace Am.Keyward.Ui.Blazor.App;

/// <summary>
/// Reference-shell implementation of <see cref="IKeywardWorkspaceContext"/>: the embedded UI operates in
/// the seeded demo tenant. A real host implements this from its own tenant selection (e.g. the active
/// tenant from membership) so the same RCL pages scope to the host's context. The software application
/// ("project") is chosen inside the UI itself (Applications page), not supplied by the host.
/// </summary>
public sealed class DemoWorkspaceContext : IKeywardWorkspaceContext
{
    public Guid TenantId => Demo.TenantId;
}
