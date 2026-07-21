using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Audit;
using Am.Keyward.Core.Domain.Software;
using Am.Keyward.Core.Domain.ValueObjects;
using Microsoft.EntityFrameworkCore;

namespace Am.Keyward.Infrastructure.Persistence;

/// <summary>
/// Manages a tenant's software projects ("Applications" in the UI). Create/rename/delete are gated on the
/// tenant-admin role (the same operator predicate as environment management); every change is audited.
/// Deleting a project takes its environments, secrets (all versions) and client tokens with it — the UI asks
/// for explicit confirmation spelling that out.
/// </summary>
public sealed class ProjectService(
    KeywardDbContext db,
    IClock clock,
    ICurrentTenant tenant,
    IAuditSink audit,
    ISoftwareClientTokenService tokens) : IProjectService
{
    private const string ResourceType = "Project";

    public async Task<IReadOnlyList<ProjectInfo>> ListAsync(Guid tenantId, CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);

        var projects = await db.Projects.AsNoTracking()
            .Where(p => p.TenantId == tenantId)
            .OrderBy(p => p.Name)
            .Select(p => new
            {
                p.Id,
                p.Name,
                p.CreatedAt,
                EnvironmentCount = db.RuntimeEnvironments.Count(e => e.ProjectId == p.Id),
                SecretCount = db.SoftwareSecrets.Count(s => s.ProjectId == p.Id),
                TokenCount = db.SoftwareClientTokens.Count(t => t.ProjectId == p.Id),
            })
            .ToListAsync(ct)
            .ConfigureAwait(false);

        return projects
            .Select(p => new ProjectInfo(p.Id, p.Name, p.CreatedAt, p.EnvironmentCount, p.SecretCount, p.TokenCount))
            .ToList();
    }

    public async Task<Guid> CreateAsync(Guid tenantId, string name, Guid? actorUserId, CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);
        await EnsureOperatorAsync(tenantId, actorUserId, ct).ConfigureAwait(false);

        var trimmed = name?.Trim() ?? "";
        await EnsureNameFreeAsync(tenantId, trimmed, exceptProjectId: null, ct).ConfigureAwait(false);

        var now = clock.UtcNow;
        var project = new Project(Guid.NewGuid(), tenantId, OwnerType.Tenant, tenantId, trimmed, now);

        // The tenant's customized default set (Administration → Default environments); no rows = built-in.
        var customDefaults = await db.TenantDefaultEnvironments
            .Where(d => d.TenantId == tenantId)
            .OrderBy(d => d.Name)
            .Select(d => d.Name)
            .ToListAsync(ct)
            .ConfigureAwait(false);
        foreach (var environment in customDefaults.Count > 0 ? customDefaults : EnvironmentName.DefaultSet)
        {
            project.AddEnvironment(Guid.NewGuid(), environment, now);
        }

        db.Projects.Add(project);
        await audit.AppendAsync(new AuditRequest(tenantId, AuditAction.Create, ResourceType, project.Id, actorUserId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);

        // Every environment starts with a pending app token (no secret yet — the value is minted on the
        // Tokens page when it is actually needed), so the token structure is visible right away.
        foreach (var environment in project.Environments)
        {
            await tokens.CreatePendingAsync(tenantId, project.Id, environment.Id, actorUserId, ct).ConfigureAwait(false);
        }

        return project.Id;
    }

    public async Task RenameAsync(Guid tenantId, Guid projectId, string name, Guid? actorUserId, CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);
        await EnsureOperatorAsync(tenantId, actorUserId, ct).ConfigureAwait(false);

        var project = await db.Projects.FirstOrDefaultAsync(p => p.Id == projectId && p.TenantId == tenantId, ct).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Project {projectId} not found.");

        var trimmed = name?.Trim() ?? "";
        await EnsureNameFreeAsync(tenantId, trimmed, exceptProjectId: projectId, ct).ConfigureAwait(false);

        project.Rename(trimmed);
        await audit.AppendAsync(new AuditRequest(tenantId, AuditAction.Update, ResourceType, projectId, actorUserId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public async Task DeleteAsync(Guid tenantId, Guid projectId, Guid? actorUserId, CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);
        await EnsureOperatorAsync(tenantId, actorUserId, ct).ConfigureAwait(false);

        var project = await db.Projects.FirstOrDefaultAsync(p => p.Id == projectId && p.TenantId == tenantId, ct).ConfigureAwait(false);
        if (project is null)
        {
            return;
        }

        // Everything scoped to the project goes with it: secrets (values + versions cascade), tokens
        // (installation-global table, so removed explicitly), then the project (environments cascade).
        var secrets = await db.SoftwareSecrets.Where(s => s.ProjectId == projectId).ToListAsync(ct).ConfigureAwait(false);
        db.SoftwareSecrets.RemoveRange(secrets);
        var tokens = await db.SoftwareClientTokens.Where(t => t.ProjectId == projectId).ToListAsync(ct).ConfigureAwait(false);
        db.SoftwareClientTokens.RemoveRange(tokens);
        db.Projects.Remove(project);

        // Each destroyed credential leaves its own trace in the audit chain (the token service promises a
        // per-token lifecycle trail), plus the project-level entry below.
        foreach (var token in tokens)
        {
            await audit.AppendAsync(new AuditRequest(tenantId, AuditAction.Delete, "SoftwareClientToken", token.Id, actorUserId), ct).ConfigureAwait(false);
        }

        await audit.AppendAsync(new AuditRequest(tenantId, AuditAction.Delete, ResourceType, projectId, actorUserId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    private async Task EnsureNameFreeAsync(Guid tenantId, string name, Guid? exceptProjectId, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            throw new ArgumentException("Project name required.", nameof(name));
        }

        if (await db.Projects.AnyAsync(
                p => p.TenantId == tenantId && p.Id != exceptProjectId && p.Name == name, ct).ConfigureAwait(false))
        {
            throw new InvalidOperationException($"An application named '{name}' already exists.");
        }
    }

    /// <summary>
    /// Whether the user may manage the software side (applications, their environments, data and tokens):
    /// a system admin, a tenant admin, OR a dedicated software manager (<see cref="AppUser.IsSoftwareManager"/>).
    /// The software-manager capability deliberately does NOT extend to groups, tenant default environments,
    /// team-vault export or break-glass — those stay tenant-admin/system-admin only.
    /// </summary>
    public async Task<bool> CanManageAsync(Guid tenantId, Guid? actorUserId, CancellationToken ct = default)
    {
        if (actorUserId is not { } actor)
        {
            return false;
        }

        return await db.Users.AnyAsync(u => u.Id == actor && (u.IsSystemAdmin || u.IsSoftwareManager), ct).ConfigureAwait(false)
            || await db.TenantMemberships.AnyAsync(
                m => m.TenantId == tenantId && m.UserId == actor && m.Role == TenantRole.TenantAdmin, ct).ConfigureAwait(false);
    }

    private async Task EnsureOperatorAsync(Guid tenantId, Guid? actorUserId, CancellationToken ct)
    {
        // A null actor is a trusted/system caller (management API authorized at the HTTP layer; seed/system
        // operations). Every UI call carries the acting user, and THAT must be a manager. (CanManageAsync
        // deliberately returns false for a null actor — it drives the read-only UI — so the null case is
        // handled here, not there.)
        if (actorUserId is null)
        {
            return;
        }

        if (!await CanManageAsync(tenantId, actorUserId, ct).ConfigureAwait(false))
        {
            throw new UnauthorizedAccessException("Managing applications requires the tenant-admin or software-manager role.");
        }
    }

    private void EnsureTenantScope(Guid requestedTenantId)
    {
        if (tenant.TenantId != requestedTenantId)
        {
            throw new UnauthorizedAccessException(
                "Tenant scope mismatch: the request's tenant does not match the authenticated scope.");
        }
    }
}
