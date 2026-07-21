namespace Am.Keyward.Core.Application;

/// <summary>
/// A tenant's software project as shown in the management UI (labelled "Application" there): the unit that
/// bundles one deployed piece of software's environments, software secrets and client tokens. The counts are
/// display data for the list.
/// </summary>
public sealed record ProjectInfo(
    Guid Id,
    string Name,
    DateTimeOffset CreatedAt,
    int EnvironmentCount,
    int SecretCount,
    int TokenCount);

/// <summary>One entry of a tenant's customized default environment set (Administration page).</summary>
public sealed record DefaultEnvironmentInfo(Guid Id, string Name);

/// <summary>
/// The tenant's default environment set — what every NEW application starts with. No rows means the tenant
/// uses the built-in set (Development/Test/Preview/Production); "Customize" copies it into editable rows,
/// and deleting all rows returns to the built-in set. Existing applications are never touched. Listing is
/// open to tenant members; mutations require the tenant-admin role.
/// </summary>
public interface IDefaultEnvironmentService
{
    Task<IReadOnlyList<DefaultEnvironmentInfo>> ListAsync(Guid tenantId, CancellationToken ct = default);

    /// <summary>Copies the built-in set into editable rows (no-op when the tenant already has rows).</summary>
    Task CustomizeAsync(Guid tenantId, Guid? actorUserId, CancellationToken ct = default);

    Task AddAsync(Guid tenantId, string name, Guid? actorUserId, CancellationToken ct = default);

    Task RenameAsync(Guid tenantId, Guid id, string name, Guid? actorUserId, CancellationToken ct = default);

    Task DeleteAsync(Guid tenantId, Guid id, Guid? actorUserId, CancellationToken ct = default);
}

/// <summary>
/// Management of a tenant's software projects ("Applications" in the UI). Listing is open to tenant members;
/// create / rename / delete require the tenant-admin role (same operator gate as environment management).
/// </summary>
public interface IProjectService
{
    Task<IReadOnlyList<ProjectInfo>> ListAsync(Guid tenantId, CancellationToken ct = default);

    /// <summary>
    /// Whether the user may manage the software side (applications, environments, data, tokens): a system
    /// admin, a tenant admin, or a software manager. For UI gating; every mutation re-checks server-side.
    /// </summary>
    Task<bool> CanManageAsync(Guid tenantId, Guid? actorUserId, CancellationToken ct = default);

    /// <summary>Creates a project with the default environment set, so secrets/tokens have a target right away.</summary>
    Task<Guid> CreateAsync(Guid tenantId, string name, Guid? actorUserId, CancellationToken ct = default);

    Task RenameAsync(Guid tenantId, Guid projectId, string name, Guid? actorUserId, CancellationToken ct = default);

    /// <summary>Deletes a project INCLUDING its environments, secrets (all versions) and client tokens.</summary>
    Task DeleteAsync(Guid tenantId, Guid projectId, Guid? actorUserId, CancellationToken ct = default);
}
