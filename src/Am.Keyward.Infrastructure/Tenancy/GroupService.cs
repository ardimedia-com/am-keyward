using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Access;
using Am.Keyward.Core.Domain.Audit;
using Am.Keyward.Core.Domain.Identity;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Am.Keyward.Infrastructure.Tenancy;

/// <summary>
/// Tenant groups (named sharing principals). Lifecycle is restricted to tenant admins / system admins;
/// member management additionally to the group's own admins; reads are open to tenant members. Every
/// mutation is audited. The tables are tenant-scoped (query filter + row-level security).
/// </summary>
public sealed class GroupService(
    KeywardDbContext db,
    IAuditSink audit,
    IClock clock,
    ICurrentTenant tenant,
    ICurrentUser currentUser) : IGroupService
{
    public async Task<Guid> CreateGroupAsync(Guid actorUserId, Guid tenantId, string name, CancellationToken ct = default)
    {
        EnsureScopes(actorUserId, tenantId);
        await EnsureGroupOperatorAsync(actorUserId, tenantId, ct).ConfigureAwait(false);

        var group = new UserGroup(Guid.NewGuid(), tenantId, name, clock.UtcNow);
        db.Groups.Add(group);
        await audit.AppendAsync(new AuditRequest(tenantId, AuditAction.Create, "Group", group.Id, actorUserId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
        return group.Id;
    }

    public async Task RenameGroupAsync(Guid actorUserId, Guid tenantId, Guid groupId, string name, CancellationToken ct = default)
    {
        EnsureScopes(actorUserId, tenantId);
        await EnsureGroupOperatorAsync(actorUserId, tenantId, ct).ConfigureAwait(false);

        var group = await LoadGroupAsync(groupId, ct).ConfigureAwait(false);
        group.Rename(name);
        await audit.AppendAsync(new AuditRequest(tenantId, AuditAction.Update, "Group", group.Id, actorUserId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public async Task DeleteGroupAsync(Guid actorUserId, Guid tenantId, Guid groupId, CancellationToken ct = default)
    {
        EnsureScopes(actorUserId, tenantId);
        await EnsureGroupOperatorAsync(actorUserId, tenantId, ct).ConfigureAwait(false);

        var group = await LoadGroupAsync(groupId, ct).ConfigureAwait(false);

        // The group's memberships and the access grants HELD BY the group go with it (no FKs to cascade).
        db.GroupMemberships.RemoveRange(await db.GroupMemberships
            .Where(m => m.GroupId == groupId).ToListAsync(ct).ConfigureAwait(false));
        db.AccessGrants.RemoveRange(await db.AccessGrants
            .Where(g => g.PrincipalType == PrincipalType.Group && g.PrincipalId == groupId)
            .ToListAsync(ct).ConfigureAwait(false));
        db.Groups.Remove(group);

        await audit.AppendAsync(new AuditRequest(tenantId, AuditAction.Delete, "Group", groupId, actorUserId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<GroupSummary>> ListGroupsAsync(Guid actorUserId, Guid tenantId, CancellationToken ct = default)
    {
        EnsureScopes(actorUserId, tenantId);

        var groups = await db.Groups
            .OrderBy(g => g.Name)
            .Select(g => new
            {
                g.Id,
                g.Name,
                MemberCount = db.GroupMemberships.Count(m => m.GroupId == g.Id),
                MyRole = db.GroupMemberships
                    .Where(m => m.GroupId == g.Id && m.UserId == actorUserId)
                    .Select(m => (GroupRole?)m.Role)
                    .FirstOrDefault(),
            })
            .ToListAsync(ct)
            .ConfigureAwait(false);

        return groups.Select(g => new GroupSummary(g.Id, g.Name, g.MemberCount, g.MyRole)).ToList();
    }

    public async Task<IReadOnlyList<GroupMemberInfo>> ListMembersAsync(Guid actorUserId, Guid tenantId, Guid groupId, CancellationToken ct = default)
    {
        EnsureScopes(actorUserId, tenantId);

        return await db.GroupMemberships
            .Where(m => m.GroupId == groupId)
            .Join(db.Users, m => m.UserId, u => u.Id, (m, u) => new { u.Id, u.DisplayName, m.Role })
            .OrderBy(x => x.DisplayName)
            .Select(x => new GroupMemberInfo(x.Id, x.DisplayName, x.Role))
            .ToListAsync(ct)
            .ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<GroupMemberInfo>> ListMemberCandidatesAsync(Guid actorUserId, Guid tenantId, CancellationToken ct = default)
    {
        EnsureScopes(actorUserId, tenantId);

        return await db.TenantMemberships
            .Where(m => m.TenantId == tenantId)
            .Join(db.Users, m => m.UserId, u => u.Id, (m, u) => new { u.Id, u.DisplayName })
            .OrderBy(x => x.DisplayName)
            .Select(x => new GroupMemberInfo(x.Id, x.DisplayName, GroupRole.Member))
            .ToListAsync(ct)
            .ConfigureAwait(false);
    }

    public async Task AddMemberAsync(Guid actorUserId, Guid tenantId, Guid groupId, Guid userId, GroupRole role, CancellationToken ct = default)
    {
        EnsureScopes(actorUserId, tenantId);
        await EnsureMemberManagerAsync(actorUserId, tenantId, groupId, ct).ConfigureAwait(false);
        await LoadGroupAsync(groupId, ct).ConfigureAwait(false);

        // Only tenant members can join a group (groups refine the tenant, they never widen it).
        if (!await db.TenantMemberships.AnyAsync(m => m.TenantId == tenantId && m.UserId == userId, ct).ConfigureAwait(false))
        {
            throw new InvalidOperationException($"User {userId} is not a member of tenant {tenantId}.");
        }

        var existing = await db.GroupMemberships
            .FirstOrDefaultAsync(m => m.GroupId == groupId && m.UserId == userId, ct).ConfigureAwait(false);
        if (existing is not null)
        {
            existing.ChangeRole(role);
        }
        else
        {
            db.GroupMemberships.Add(new GroupMembership(Guid.NewGuid(), tenantId, groupId, userId, role, clock.UtcNow));
        }

        await audit.AppendAsync(new AuditRequest(tenantId, AuditAction.Grant, "Group", groupId, actorUserId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public async Task RemoveMemberAsync(Guid actorUserId, Guid tenantId, Guid groupId, Guid userId, CancellationToken ct = default)
    {
        EnsureScopes(actorUserId, tenantId);
        await EnsureMemberManagerAsync(actorUserId, tenantId, groupId, ct).ConfigureAwait(false);

        var membership = await db.GroupMemberships
            .FirstOrDefaultAsync(m => m.GroupId == groupId && m.UserId == userId, ct).ConfigureAwait(false);
        if (membership is null)
        {
            return;
        }

        db.GroupMemberships.Remove(membership);
        await audit.AppendAsync(new AuditRequest(tenantId, AuditAction.Revoke, "Group", groupId, actorUserId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public Task SetMemberRoleAsync(Guid actorUserId, Guid tenantId, Guid groupId, Guid userId, GroupRole role, CancellationToken ct = default) =>
        AddMemberAsync(actorUserId, tenantId, groupId, userId, role, ct); // add-or-update semantics

    public async Task<bool> CanManageGroupsAsync(Guid actorUserId, Guid tenantId, CancellationToken ct = default)
    {
        EnsureScopes(actorUserId, tenantId);
        return await IsGroupOperatorAsync(actorUserId, tenantId, ct).ConfigureAwait(false);
    }

    // --- guards ---

    private void EnsureScopes(Guid actorUserId, Guid tenantId)
    {
        if (currentUser.UserId != actorUserId)
        {
            throw new UnauthorizedAccessException("Acting user does not match the established user scope.");
        }

        if (tenant.TenantId != tenantId)
        {
            throw new UnauthorizedAccessException("Tenant does not match the established tenant scope.");
        }
    }

    private async Task<UserGroup> LoadGroupAsync(Guid groupId, CancellationToken ct) =>
        await db.Groups.FirstOrDefaultAsync(g => g.Id == groupId, ct).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Group {groupId} not found.");

    private async Task<bool> IsGroupOperatorAsync(Guid actorUserId, Guid tenantId, CancellationToken ct) =>
        await db.Users.AnyAsync(u => u.Id == actorUserId && u.IsSystemAdmin, ct).ConfigureAwait(false)
        || await db.TenantMemberships.AnyAsync(
            m => m.TenantId == tenantId && m.UserId == actorUserId && m.Role == TenantRole.TenantAdmin, ct).ConfigureAwait(false);

    private async Task EnsureGroupOperatorAsync(Guid actorUserId, Guid tenantId, CancellationToken ct)
    {
        if (!await IsGroupOperatorAsync(actorUserId, tenantId, ct).ConfigureAwait(false))
        {
            throw new UnauthorizedAccessException("Managing groups requires the tenant-admin role.");
        }
    }

    private async Task EnsureMemberManagerAsync(Guid actorUserId, Guid tenantId, Guid groupId, CancellationToken ct)
    {
        if (await IsGroupOperatorAsync(actorUserId, tenantId, ct).ConfigureAwait(false))
        {
            return;
        }

        var isGroupAdmin = await db.GroupMemberships.AnyAsync(
            m => m.GroupId == groupId && m.UserId == actorUserId && m.Role == GroupRole.Admin, ct).ConfigureAwait(false);
        if (!isGroupAdmin)
        {
            throw new UnauthorizedAccessException("Managing group members requires the tenant-admin role or group admin.");
        }
    }
}
