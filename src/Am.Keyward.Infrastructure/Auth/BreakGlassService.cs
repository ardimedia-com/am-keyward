using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Access;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Am.Keyward.Infrastructure.Auth;

/// <summary>
/// Dual-control break-glass: a System Admin requests emergency access to a server-side resource with a
/// reason; a <em>different</em> System Admin must approve it before it can be consumed for a single recovery
/// inside its validity window. Every transition is recorded both in the tamper-evident audit chain and in
/// the out-of-band <see cref="IBreakGlassSink"/> (which the DB admin cannot rewrite). The grant table is
/// installation-global: break-glass is a cross-tenant System-Admin capability gated by an explicit
/// system-admin check, not by tenant scope.
/// </summary>
public sealed class BreakGlassService(
    KeywardDbContext db,
    IBreakGlassSink sink,
    IAuditSink audit,
    IClock clock,
    IOptions<BreakGlassOptions> options) : IBreakGlassService
{
    public async Task<Guid> RequestAsync(RequestBreakGlassCommand cmd, CancellationToken ct = default)
    {
        await EnsureSystemAdminAsync(cmd.RequesterUserId, ct).ConfigureAwait(false);

        var now = clock.UtcNow;
        var grant = new BreakGlassGrant(
            Guid.NewGuid(), cmd.TenantId, cmd.Scope, cmd.RequesterUserId, cmd.Reason,
            now, now.AddMinutes(Math.Max(1, options.Value.ValidityMinutes)));

        db.BreakGlassGrants.Add(grant);
        await audit.AppendAsync(new AuditRequest(grant.TenantId, AuditAction.BreakGlass, "BreakGlassGrant", grant.Id, cmd.RequesterUserId), ct).ConfigureAwait(false);
        await WriteSinkAsync("Requested", grant, cmd.RequesterUserId, ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
        return grant.Id;
    }

    public async Task ApproveAsync(Guid grantId, Guid approverUserId, CancellationToken ct = default)
    {
        await EnsureSystemAdminAsync(approverUserId, ct).ConfigureAwait(false);
        var grant = await LoadAsync(grantId, ct).ConfigureAwait(false);

        grant.Approve(approverUserId, clock.UtcNow); // domain enforces approver != requester (dual control)

        // The non-repudiable approval record goes out-of-band first, so it survives even if the DB write fails.
        await WriteSinkAsync("Approved", grant, approverUserId, ct).ConfigureAwait(false);
        await audit.AppendAsync(new AuditRequest(grant.TenantId, AuditAction.BreakGlass, "BreakGlassGrant", grant.Id, approverUserId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public async Task RejectAsync(Guid grantId, Guid approverUserId, CancellationToken ct = default)
    {
        await EnsureSystemAdminAsync(approverUserId, ct).ConfigureAwait(false);
        var grant = await LoadAsync(grantId, ct).ConfigureAwait(false);

        grant.Reject(approverUserId, clock.UtcNow);

        await WriteSinkAsync("Rejected", grant, approverUserId, ct).ConfigureAwait(false);
        await audit.AppendAsync(new AuditRequest(grant.TenantId, AuditAction.BreakGlass, "BreakGlassGrant", grant.Id, approverUserId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<BreakGlassGrant>> ListPendingAsync(CancellationToken ct = default) =>
        await db.BreakGlassGrants
            .Where(g => g.Status == BreakGlassStatus.Pending)
            .OrderBy(g => g.RequestedAt)
            .ToListAsync(ct)
            .ConfigureAwait(false);

    public Task<bool> IsSystemAdminAsync(Guid userId, CancellationToken ct = default) =>
        db.Users.AsNoTracking().AnyAsync(u => u.Id == userId && u.IsSystemAdmin, ct);

    public async Task<IReadOnlyList<BreakGlassTargetVault>> ListTargetVaultsAsync(Guid actorUserId, Guid tenantId, CancellationToken ct = default)
    {
        await EnsureSystemAdminAsync(actorUserId, ct).ConfigureAwait(false);

        // Metadata only (id + name) — the recovery target picker. The tenant query filter already scopes
        // this to the current tenant; the explicit TenantId predicate additionally excludes the caller's
        // own personal vaults (TenantId == null), which are out of break-glass scope by design.
        return await db.Vaults
            .Where(v => v.TenantId == tenantId)
            .OrderBy(v => v.Name)
            .Select(v => new BreakGlassTargetVault(v.Id, v.Name))
            .ToListAsync(ct)
            .ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<BreakGlassGrantInfo>> ListGrantsAsync(Guid actorUserId, int take = 50, CancellationToken ct = default)
    {
        await EnsureSystemAdminAsync(actorUserId, ct).ConfigureAwait(false);

        var grants = await db.BreakGlassGrants.AsNoTracking()
            .OrderByDescending(g => g.RequestedAt)
            .Take(Math.Clamp(take, 1, 200))
            .ToListAsync(ct)
            .ConfigureAwait(false);
        if (grants.Count == 0)
        {
            return [];
        }

        // Resolve display names in memory (the sets are tiny). Users are installation-global; vault names
        // resolve only within the current tenant scope (a foreign tenant's grant shows without a name).
        var userIds = grants.Select(g => g.RequesterUserId)
            .Concat(grants.Where(g => g.ApproverUserId is not null).Select(g => g.ApproverUserId!.Value))
            .Distinct().ToList();
        var users = await db.Users.AsNoTracking()
            .Where(u => userIds.Contains(u.Id))
            .ToDictionaryAsync(u => u.Id, u => u.DisplayName, ct)
            .ConfigureAwait(false);

        var vaultIds = grants.Where(g => g.Scope.Kind == GrantScopeKind.Vault).Select(g => g.Scope.TargetId).Distinct().ToList();
        var vaultNames = await db.Vaults.AsNoTracking()
            .Where(v => vaultIds.Contains(v.Id))
            .ToDictionaryAsync(v => v.Id, v => v.Name, ct)
            .ConfigureAwait(false);

        return grants.Select(g => new BreakGlassGrantInfo(
            g.Id, g.Status, g.Scope,
            g.Scope.Kind == GrantScopeKind.Vault && vaultNames.TryGetValue(g.Scope.TargetId, out var name) ? name : null,
            g.RequesterUserId, users.GetValueOrDefault(g.RequesterUserId, g.RequesterUserId.ToString("D")),
            g.ApproverUserId, g.ApproverUserId is { } a ? users.GetValueOrDefault(a, a.ToString("D")) : null,
            g.Reason, g.RequestedAt, g.DecidedAt, g.ExpiresAt, g.ConsumedAt)).ToList();
    }

    public async Task ConsumeAsync(Guid grantId, Guid actorUserId, CancellationToken ct = default)
    {
        // Re-check system-admin at consume time (mirrors request/approve/reject): a user de-privileged after
        // approval must not still be able to consume an outstanding grant.
        await EnsureSystemAdminAsync(actorUserId, ct).ConfigureAwait(false);

        var grant = await LoadAsync(grantId, ct).ConfigureAwait(false);
        if (grant.ApproverUserId != actorUserId && grant.RequesterUserId != actorUserId)
        {
            throw new UnauthorizedAccessException("Only the break-glass requester or approver may consume the grant.");
        }

        // The materialized access grant below is tenant-scoped (the ACL query filter and RLS admit only
        // tenant rows), so a tenant-less target cannot be recovered this way — personal vaults are out of
        // break-glass scope by design (their access model is "owner only", not the ACL).
        if (grant.TenantId is null)
        {
            throw new InvalidOperationException("Break-glass consumption requires a tenant-scoped target resource.");
        }

        grant.Consume(clock.UtcNow); // domain enforces approved-and-unexpired

        // Materialize the emergency access as a REGULAR Manage grant for the REQUESTER (not the actor — the
        // approver may click consume, but the access belongs to whoever needs the recovery). It shows up in
        // the normal ACL: visible on the vault's share list, enforced by the existing authorization checks,
        // and revocable after the recovery — no second, invisible authorization path.
        var existing = await db.AccessGrants.FirstOrDefaultAsync(
            g => g.PrincipalType == PrincipalType.User && g.PrincipalId == grant.RequesterUserId
                && g.Scope.Kind == grant.Scope.Kind && g.Scope.TargetId == grant.Scope.TargetId,
            ct).ConfigureAwait(false);
        if (existing is null)
        {
            db.AccessGrants.Add(new AccessGrant(
                Guid.NewGuid(), grant.TenantId, PrincipalType.User, grant.RequesterUserId,
                grant.Scope, Permission.Manage, actorUserId, clock.UtcNow));
        }
        else if (existing.Permission < Permission.Manage)
        {
            existing.ChangePermission(Permission.Manage);
        }

        await WriteSinkAsync("Consumed", grant, actorUserId, ct).ConfigureAwait(false);
        await audit.AppendAsync(new AuditRequest(grant.TenantId, AuditAction.BreakGlass, "BreakGlassGrant", grant.Id, actorUserId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    private async Task<BreakGlassGrant> LoadAsync(Guid grantId, CancellationToken ct) =>
        await db.BreakGlassGrants.FirstOrDefaultAsync(g => g.Id == grantId, ct).ConfigureAwait(false)
        ?? throw new InvalidOperationException($"Break-glass grant {grantId} not found.");

    private async Task EnsureSystemAdminAsync(Guid userId, CancellationToken ct)
    {
        var isAdmin = await db.Users.AsNoTracking().AnyAsync(u => u.Id == userId && u.IsSystemAdmin, ct).ConfigureAwait(false);
        if (!isAdmin)
        {
            throw new UnauthorizedAccessException("Break-glass is restricted to System Admins.");
        }
    }

    private Task WriteSinkAsync(string @event, BreakGlassGrant grant, Guid actorUserId, CancellationToken ct) =>
        sink.AppendAsync(new BreakGlassRecord(
            clock.UtcNow, @event, grant.Id, grant.TenantId,
            $"{grant.Scope.Kind}:{grant.Scope.TargetId}", grant.RequesterUserId,
            @event == "Requested" ? null : actorUserId, grant.Reason), ct);
}
