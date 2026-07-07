using Am.Keyward.Core.Domain;

namespace Am.Keyward.Core.Application;

/// <summary>A tenant group (a shareable principal); MyRole is the acting user's role in it (null = not a member).</summary>
public sealed record GroupSummary(Guid Id, string Name, int MemberCount, GroupRole? MyRole);

/// <summary>One member of a group.</summary>
public sealed record GroupMemberInfo(Guid UserId, string DisplayName, GroupRole Role);

/// <summary>
/// Tenant groups: named sets of tenant members used as sharing principals — share a vault once with "IT"
/// instead of with each person. Group lifecycle (create/rename/delete) is for tenant admins (and system
/// admins); member management additionally for the group's own admins. Reads are open to tenant members.
/// </summary>
public interface IGroupService
{
    Task<Guid> CreateGroupAsync(Guid actorUserId, Guid tenantId, string name, CancellationToken ct = default);
    Task RenameGroupAsync(Guid actorUserId, Guid tenantId, Guid groupId, string name, CancellationToken ct = default);

    /// <summary>Deletes the group, its memberships and every access grant held by it.</summary>
    Task DeleteGroupAsync(Guid actorUserId, Guid tenantId, Guid groupId, CancellationToken ct = default);

    Task<IReadOnlyList<GroupSummary>> ListGroupsAsync(Guid actorUserId, Guid tenantId, CancellationToken ct = default);
    Task<IReadOnlyList<GroupMemberInfo>> ListMembersAsync(Guid actorUserId, Guid tenantId, Guid groupId, CancellationToken ct = default);

    /// <summary>Tenant members that can be added to a group (includes the actor).</summary>
    Task<IReadOnlyList<GroupMemberInfo>> ListMemberCandidatesAsync(Guid actorUserId, Guid tenantId, CancellationToken ct = default);

    Task AddMemberAsync(Guid actorUserId, Guid tenantId, Guid groupId, Guid userId, GroupRole role, CancellationToken ct = default);
    Task RemoveMemberAsync(Guid actorUserId, Guid tenantId, Guid groupId, Guid userId, CancellationToken ct = default);
    Task SetMemberRoleAsync(Guid actorUserId, Guid tenantId, Guid groupId, Guid userId, GroupRole role, CancellationToken ct = default);

    /// <summary>True when the actor may create/rename/delete groups (tenant admin or system admin).</summary>
    Task<bool> CanManageGroupsAsync(Guid actorUserId, Guid tenantId, CancellationToken ct = default);
}
