using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Identity;
using Am.Keyward.Core.Domain.Software;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using KeywardEnvironmentName = Am.Keyward.Core.Domain.ValueObjects.EnvironmentName;

namespace Am.Keyward.Infrastructure.Tenancy;

/// <summary>
/// Insert-only startup seed for a <b>single-organization host</b>: the one fixed tenant every signed-in user
/// belongs to, and — optionally — the software application ("project") that holds that host's own machine
/// credentials, with the default environment set.
/// <para>
/// Both ids are supplied by the host and must be STABLE constants, so the seed and the just-in-time
/// memberships always agree and re-running the seed is a no-op. No secret values are written; safe to run on
/// every startup.
/// </para>
/// <para>
/// <b>Must run inside the tenant's scope</b> (<see cref="ITenantScopeSetter.SetTenant"/>): row-level security
/// admits the rows only when <c>SESSION_CONTEXT('TenantId')</c> equals the row's tenant. The existence checks
/// bypass the tenant query filter so a partially-seeded database is completed rather than duplicated.
/// </para>
/// <para>
/// The project is created DIRECTLY rather than through <c>IProjectService.CreateAsync</c>, which requires a
/// signed-in tenant-admin actor — at startup there is none.
/// </para>
/// </summary>
public static class KeywardSingleTenantSeeder
{
    /// <summary>
    /// Ensures the tenant exists, and — when <paramref name="applicationId"/> and
    /// <paramref name="applicationName"/> are given — the host's own machine-secrets application with the
    /// default environments (Development / Test / Preview / Production).
    /// </summary>
    /// <param name="db">A context inside the tenant's scope.</param>
    /// <param name="clock">Timestamp source (UTC).</param>
    /// <param name="tenantId">Stable id of the single tenant.</param>
    /// <param name="tenantName">Display name of the operating organization.</param>
    /// <param name="applicationId">Stable id of the host's own application, or <c>null</c> to seed no application.</param>
    /// <param name="applicationName">Its name — by convention the deployed host's assembly name.</param>
    public static async Task EnsureSeededAsync(
        KeywardDbContext db,
        IClock clock,
        Guid tenantId,
        string tenantName,
        Guid? applicationId = null,
        string? applicationName = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(db);
        ArgumentNullException.ThrowIfNull(clock);
        ArgumentException.ThrowIfNullOrWhiteSpace(tenantName);

        DateTimeOffset now = clock.UtcNow;

        if (!await db.Tenants.IgnoreQueryFilters().AnyAsync(t => t.Id == tenantId, cancellationToken).ConfigureAwait(false))
        {
            db.Tenants.Add(new Tenant(tenantId, tenantName, isSystemTenant: true, now));
            await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }

        if (applicationId is not { } projectId || string.IsNullOrWhiteSpace(applicationName))
        {
            return;
        }

        if (!await db.Projects.IgnoreQueryFilters().AnyAsync(p => p.Id == projectId, cancellationToken).ConfigureAwait(false))
        {
            Project project = new(projectId, tenantId, OwnerType.Tenant, tenantId, applicationName, now);
            foreach (KeywardEnvironmentName environment in KeywardEnvironmentName.DefaultSet)
            {
                project.AddEnvironment(Guid.NewGuid(), environment, now);
            }

            db.Projects.Add(project);
            await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
    }
}
