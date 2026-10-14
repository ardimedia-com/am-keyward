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
    IDbContextFactory<KeywardDbContext> dbFactory,
    IClock clock,
    ICurrentTenant tenant,
    DbAuditSink audit,
    ISoftwareClientTokenService tokens,
    ICurrentUser currentUser,
    ICurrentActor actor) : IProjectService
{
    private const string ResourceType = "Project";

    public async Task<IReadOnlyList<ProjectInfo>> ListAsync(Guid tenantId, CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);

        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
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

    public async Task<IReadOnlyList<ApplicationSearchHit>> SearchAsync(Guid tenantId, Guid? actorUserId, string query, CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);
        var term = query?.Trim() ?? "";
        if (term.Length < 2)
        {
            return [];
        }

        bool Matches(string? text) => text is { Length: > 0 } && text.Contains(term, StringComparison.OrdinalIgnoreCase);

        // A tenant holds tens of applications and a few hundred keys: read the names once and match in memory, which
        // also covers the value-object columns (EnvironmentName, SecretKey) a database LIKE cannot reach.
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var apps = await db.Projects.AsNoTracking()
            .Where(p => p.TenantId == tenantId)
            .Select(p => new { p.Id, p.Name })
            .ToListAsync(ct)
            .ConfigureAwait(false);
        var names = apps.ToDictionary(a => a.Id, a => a.Name);
        var ids = names.Keys.ToList();
        var environments = (await db.RuntimeEnvironments.AsNoTracking()
                .Where(e => ids.Contains(e.ProjectId))
                .Select(e => new { e.Id, e.ProjectId, e.Name, e.SortOrder })
                .ToListAsync(ct)
                .ConfigureAwait(false))
            .Select(e => (e.Id, e.ProjectId, Name: e.Name.Value, e.SortOrder))
            .ToList();
        var environmentNames = environments.ToDictionary(e => e.Id, e => e.Name);

        var hits = new List<ApplicationSearchHit>();
        hits.AddRange(apps.Where(a => Matches(a.Name)).Select(a => new ApplicationSearchHit(a.Id, a.Name, ApplicationSearchField.Application)));
        hits.AddRange(environments.Where(e => Matches(e.Name))
            .Select(e => new ApplicationSearchHit(e.ProjectId, names[e.ProjectId], ApplicationSearchField.Environment, e.Name, e.Name)));

        if (await CanManageAsync(db, tenantId, actorUserId, ct).ConfigureAwait(false))
        {
            var keys = (await db.SoftwareSecrets.AsNoTracking()
                    .Where(s => ids.Contains(s.ProjectId))
                    .Select(s => new { s.Id, s.ProjectId, s.Key })
                    .ToListAsync(ct)
                    .ConfigureAwait(false))
                .Select(s => (s.Id, s.ProjectId, Key: s.Key.Value))
                .ToList();
            hits.AddRange(keys.Where(k => Matches(k.Key))
                .Select(k => new ApplicationSearchHit(k.ProjectId, names[k.ProjectId], ApplicationSearchField.Key, k.Key)));

            var keyIds = keys.Select(k => k.Id).ToList();
            var keyById = keys.ToDictionary(k => k.Id);
            var notes = await db.SecretValues.AsNoTracking()
                .Where(v => keyIds.Contains(v.SoftwareSecretId) && v.Note != "")
                .Select(v => new { v.SoftwareSecretId, v.EnvironmentId, v.Note })
                .ToListAsync(ct)
                .ConfigureAwait(false);
            hits.AddRange(notes.Where(n => Matches(n.Note)).Select(n =>
            {
                var key = keyById[n.SoftwareSecretId];
                return new ApplicationSearchHit(key.ProjectId, names[key.ProjectId], ApplicationSearchField.RotationNote, key.Key,
                    environmentNames.GetValueOrDefault(n.EnvironmentId));
            }));

            var tokens = await db.SoftwareClientTokens.AsNoTracking()
                .Where(t => t.TenantId == tenantId && ids.Contains(t.ProjectId))
                .Select(t => new { t.Id, t.ProjectId, t.EnvironmentId, t.Name, t.Note })
                .ToListAsync(ct)
                .ConfigureAwait(false);
            hits.AddRange(tokens.Where(t => Matches(t.Name) || Matches(t.Note)).Select(t =>
                new ApplicationSearchHit(t.ProjectId, names[t.ProjectId], ApplicationSearchField.Token, t.Name,
                    environmentNames.GetValueOrDefault(t.EnvironmentId), t.Id)));
        }

        return hits
            .OrderBy(h => h.Application, StringComparer.OrdinalIgnoreCase)
            .ThenBy(h => h.Field)
            .ThenBy(h => h.Detail, StringComparer.OrdinalIgnoreCase)
            .ThenBy(h => h.Environment, StringComparer.OrdinalIgnoreCase)
            .Take(IProjectService.MaxSearchHits)
            .ToList();
    }

    public async Task<Guid> CreateAsync(Guid tenantId, string name, Guid? actorUserId, CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        await EnsureOperatorAsync(db, tenantId, actorUserId, ct).ConfigureAwait(false);

        var trimmed = name?.Trim() ?? "";
        await EnsureNameFreeAsync(db, tenantId, trimmed, exceptProjectId: null, ct).ConfigureAwait(false);

        var now = clock.UtcNow;
        var project = new Project(Guid.NewGuid(), tenantId, OwnerType.Tenant, tenantId, trimmed, now);
        if (actor is { Kind: ActorKind.Agent, TokenId: { } agentTokenId })
        {
            project.MarkCreatedByAgent(agentTokenId);
        }

        // The tenant's customized default set (Administration → Default environments); no rows = built-in.
        // Ordered by the set's display order so the project's environments inherit it (AddEnvironment
        // assigns 0..n-1 in iteration order).
        var customDefaults = await db.TenantDefaultEnvironments
            .Where(d => d.TenantId == tenantId)
            .OrderBy(d => d.SortOrder).ThenBy(d => d.Name)
            .Select(d => d.Name)
            .ToListAsync(ct)
            .ConfigureAwait(false);
        foreach (var environment in customDefaults.Count > 0 ? customDefaults : EnvironmentName.DefaultSet)
        {
            project.AddEnvironment(Guid.NewGuid(), environment, now);
        }

        db.Projects.Add(project);
        await audit.AppendAsync(db, new AuditRequest(tenantId, AuditAction.Create, ResourceType, project.Id, actorUserId), ct).ConfigureAwait(false);
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
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        await EnsureOperatorAsync(db, tenantId, actorUserId, ct).ConfigureAwait(false);

        var project = await db.Projects.FirstOrDefaultAsync(p => p.Id == projectId && p.TenantId == tenantId, ct).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Project {projectId} not found.");

        var trimmed = name?.Trim() ?? "";
        await EnsureNameFreeAsync(db, tenantId, trimmed, exceptProjectId: projectId, ct).ConfigureAwait(false);

        project.Rename(trimmed);
        await audit.AppendAsync(db, new AuditRequest(tenantId, AuditAction.Update, ResourceType, projectId, actorUserId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public async Task DeleteAsync(Guid tenantId, Guid projectId, Guid? actorUserId, CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        await EnsureOperatorAsync(db, tenantId, actorUserId, ct).ConfigureAwait(false);

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
            await audit.AppendAsync(db, new AuditRequest(tenantId, AuditAction.Delete, "SoftwareClientToken", token.Id, actorUserId), ct).ConfigureAwait(false);
        }

        await audit.AppendAsync(db, new AuditRequest(tenantId, AuditAction.Delete, ResourceType, projectId, actorUserId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    private static async Task EnsureNameFreeAsync(KeywardDbContext db, Guid tenantId, string name, Guid? exceptProjectId, CancellationToken ct)
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
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        return await CanManageAsync(db, tenantId, actorUserId, ct).ConfigureAwait(false);
    }

    // CanManageAsync deliberately returns false for a null actor — it drives the read-only UI.
    private static Task<bool> CanManageAsync(KeywardDbContext db, Guid tenantId, Guid? actorUserId, CancellationToken ct) =>
        SoftwareOperatorGuard.IsOperatorAsync(db, tenantId, actorUserId, ct);

    private Task EnsureOperatorAsync(KeywardDbContext db, Guid tenantId, Guid? actorUserId, CancellationToken ct) =>
        SoftwareOperatorGuard.EnsureOperatorAsync(db, tenantId, actorUserId, currentUser, actor,
            "Managing applications requires the tenant-admin or software-manager role.", ct);

    private void EnsureTenantScope(Guid requestedTenantId)
    {
        if (tenant.TenantId != requestedTenantId)
        {
            throw new UnauthorizedAccessException(
                "Tenant scope mismatch: the request's tenant does not match the authenticated scope.");
        }
    }
}
