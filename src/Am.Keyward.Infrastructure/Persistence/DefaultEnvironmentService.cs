using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Audit;
using Am.Keyward.Core.Domain.Software;
using Am.Keyward.Core.Domain.ValueObjects;
using Microsoft.EntityFrameworkCore;

namespace Am.Keyward.Infrastructure.Persistence;

/// <summary>
/// Maintains the tenant's default environment set (Administration page): the environments every NEW
/// application starts with. No rows = the built-in <see cref="EnvironmentName.DefaultSet"/>; "Customize"
/// materializes it into editable rows, deleting all rows returns to the built-in set. Mutations are gated
/// on the tenant-admin role and audited; existing applications are never touched.
/// </summary>
public sealed class DefaultEnvironmentService(
    KeywardDbContext db,
    IClock clock,
    ICurrentTenant tenant,
    IAuditSink audit) : IDefaultEnvironmentService
{
    private const string ResourceType = "DefaultEnvironment";

    public async Task<IReadOnlyList<DefaultEnvironmentInfo>> ListAsync(Guid tenantId, CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);

        var rows = await db.TenantDefaultEnvironments.AsNoTracking()
            .Where(d => d.TenantId == tenantId)
            .OrderBy(d => d.Name)
            .ToListAsync(ct)
            .ConfigureAwait(false);
        return rows.Select(d => new DefaultEnvironmentInfo(d.Id, d.Name.Value)).ToList();
    }

    public async Task CustomizeAsync(Guid tenantId, Guid? actorUserId, CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);
        await EnsureOperatorAsync(tenantId, actorUserId, ct).ConfigureAwait(false);

        if (await db.TenantDefaultEnvironments.AnyAsync(d => d.TenantId == tenantId, ct).ConfigureAwait(false))
        {
            return;
        }

        var now = clock.UtcNow;
        foreach (var name in EnvironmentName.DefaultSet)
        {
            var row = new TenantDefaultEnvironment(Guid.NewGuid(), tenantId, name, now);
            db.TenantDefaultEnvironments.Add(row);
            await audit.AppendAsync(new AuditRequest(tenantId, AuditAction.Create, ResourceType, row.Id, actorUserId), ct).ConfigureAwait(false);
        }

        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public async Task AddAsync(Guid tenantId, string name, Guid? actorUserId, CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);
        await EnsureOperatorAsync(tenantId, actorUserId, ct).ConfigureAwait(false);

        var environmentName = EnvironmentName.Create(name);
        await EnsureNameFreeAsync(tenantId, environmentName, exceptId: null, ct).ConfigureAwait(false);

        var row = new TenantDefaultEnvironment(Guid.NewGuid(), tenantId, environmentName, clock.UtcNow);
        db.TenantDefaultEnvironments.Add(row);
        await audit.AppendAsync(new AuditRequest(tenantId, AuditAction.Create, ResourceType, row.Id, actorUserId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public async Task RenameAsync(Guid tenantId, Guid id, string name, Guid? actorUserId, CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);
        await EnsureOperatorAsync(tenantId, actorUserId, ct).ConfigureAwait(false);

        var row = await db.TenantDefaultEnvironments.FirstOrDefaultAsync(d => d.Id == id && d.TenantId == tenantId, ct).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Default environment {id} not found.");

        var environmentName = EnvironmentName.Create(name);
        await EnsureNameFreeAsync(tenantId, environmentName, exceptId: id, ct).ConfigureAwait(false);

        row.Rename(environmentName);
        await audit.AppendAsync(new AuditRequest(tenantId, AuditAction.Update, ResourceType, id, actorUserId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public async Task DeleteAsync(Guid tenantId, Guid id, Guid? actorUserId, CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);
        await EnsureOperatorAsync(tenantId, actorUserId, ct).ConfigureAwait(false);

        var row = await db.TenantDefaultEnvironments.FirstOrDefaultAsync(d => d.Id == id && d.TenantId == tenantId, ct).ConfigureAwait(false);
        if (row is null)
        {
            return;
        }

        // Deleting the LAST row is allowed on purpose: it returns the tenant to the built-in default set.
        db.TenantDefaultEnvironments.Remove(row);
        await audit.AppendAsync(new AuditRequest(tenantId, AuditAction.Delete, ResourceType, id, actorUserId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    private async Task EnsureNameFreeAsync(Guid tenantId, EnvironmentName name, Guid? exceptId, CancellationToken ct)
    {
        if (await db.TenantDefaultEnvironments.AnyAsync(
                d => d.TenantId == tenantId && d.Id != exceptId && d.Name == name, ct).ConfigureAwait(false))
        {
            throw new InvalidOperationException($"Default environment '{name}' already exists.");
        }
    }

    private async Task EnsureOperatorAsync(Guid tenantId, Guid? actorUserId, CancellationToken ct)
    {
        var isOperator = actorUserId is { } actor
            && (await db.Users.AnyAsync(u => u.Id == actor && u.IsSystemAdmin, ct).ConfigureAwait(false)
                || await db.TenantMemberships.AnyAsync(
                    m => m.TenantId == tenantId && m.UserId == actor && m.Role == TenantRole.TenantAdmin, ct).ConfigureAwait(false));
        if (!isOperator)
        {
            throw new UnauthorizedAccessException("Managing default environments requires the tenant-admin role.");
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
