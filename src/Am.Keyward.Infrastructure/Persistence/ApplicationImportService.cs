using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Microsoft.EntityFrameworkCore;

namespace Am.Keyward.Infrastructure.Persistence;

/// <summary>
/// Bulk import of applications and secret keys (never values), composed from the existing audited
/// services: new applications go through <see cref="IProjectService.CreateAsync"/> (default environment
/// set + pending app tokens), new keys through <see cref="ISoftwareSecretService.CreateSecretAsync"/>.
/// Each created entity commits in its own operation, which is safe because the import is additive and
/// idempotent — a re-run after a mid-import failure simply completes the remainder (existing
/// applications/keys are skipped, nothing is ever overwritten or deleted).
/// </summary>
public sealed class ApplicationImportService(
    IDbContextFactory<KeywardDbContext> dbFactory,
    ICurrentTenant tenant,
    IProjectService projects,
    ISoftwareSecretService secrets) : IApplicationImportService
{
    public async Task<ApplicationImportPreview> PreviewAsync(Guid tenantId, ApplicationImportPlan plan, CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);

        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var existingProjects = await db.Projects.AsNoTracking()
            .Where(p => p.TenantId == tenantId)
            .Select(p => new { p.Id, p.Name })
            .ToListAsync(ct)
            .ConfigureAwait(false);

        var entries = new List<ApplicationImportPreviewEntry>();
        foreach (var application in plan.Applications)
        {
            var existing = existingProjects.FirstOrDefault(
                p => string.Equals(p.Name, application.Name, StringComparison.OrdinalIgnoreCase));

            var existingKeys = existing is null
                ? []
                : await db.SoftwareSecrets.AsNoTracking()
                    .Where(s => s.ProjectId == existing.Id)
                    .Select(s => s.Key)
                    .ToListAsync(ct)
                    .ConfigureAwait(false);

            entries.Add(new ApplicationImportPreviewEntry(
                application.Name,
                existing is not null,
                application.Keys
                    .Select(k => new ApplicationImportPreviewKey(
                        k, existingKeys.Any(e => string.Equals(e.Value, k, StringComparison.OrdinalIgnoreCase))))
                    .ToList()));
        }

        return new ApplicationImportPreview(entries);
    }

    public async Task<ApplicationImportResult> ImportAsync(Guid tenantId, ApplicationImportPlan plan, Guid? actorUserId, CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);
        if (!plan.IsValid)
        {
            throw new InvalidOperationException("The import plan has parse errors and cannot be executed.");
        }

        // Fail fast before creating anything (each composed call re-checks server-side anyway). A null
        // actor is a trusted/system caller, consistent with the composed services.
        if (actorUserId is not null && !await projects.CanManageAsync(tenantId, actorUserId, ct).ConfigureAwait(false))
        {
            throw new UnauthorizedAccessException("Importing applications requires the tenant-admin or software-manager role.");
        }

        var applicationsCreated = 0;
        var secretsCreated = 0;
        var secretsSkipped = 0;

        foreach (var application in plan.Applications)
        {
            var projectId = await FindProjectIdAsync(tenantId, application.Name, ct).ConfigureAwait(false);
            if (projectId is null)
            {
                projectId = await projects.CreateAsync(tenantId, application.Name, actorUserId, ct).ConfigureAwait(false);
                applicationsCreated++;
            }

            foreach (var key in application.Keys)
            {
                var created = await secrets.CreateSecretAsync(tenantId, projectId.Value, key, actorUserId, ct).ConfigureAwait(false);
                if (created)
                {
                    secretsCreated++;
                }
                else
                {
                    secretsSkipped++;
                }
            }
        }

        return new ApplicationImportResult(applicationsCreated, secretsCreated, secretsSkipped);
    }

    private async Task<Guid?> FindProjectIdAsync(Guid tenantId, string name, CancellationToken ct)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var candidates = await db.Projects.AsNoTracking()
            .Where(p => p.TenantId == tenantId)
            .Select(p => new { p.Id, p.Name })
            .ToListAsync(ct)
            .ConfigureAwait(false);
        return candidates.FirstOrDefault(p => string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase))?.Id;
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
