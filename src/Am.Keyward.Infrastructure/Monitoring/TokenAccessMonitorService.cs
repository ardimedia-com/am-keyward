using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Audit;
using Am.Keyward.Core.Domain.Software;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Am.Keyward.Infrastructure.Monitoring;

/// <summary>
/// Management side of heartbeat monitoring (the Applications page's Monitoring tab): list the monitors of
/// an application's tokens with their computed next deadline, and create/update/pause them. Mutations are
/// gated on the software-operator predicate (system admin, tenant admin or software manager) and audited —
/// the same posture as token management. Evaluation itself happens in
/// <see cref="TokenAccessMonitorBackgroundService"/>.
/// </summary>
public sealed class TokenAccessMonitorService(
    IDbContextFactory<KeywardDbContext> dbFactory,
    IClock clock,
    ICurrentTenant tenant,
    DbAuditSink audit,
    IOptions<MonitoringOptions> options) : ITokenAccessMonitorService
{
    private const string ResourceType = "TokenAccessMonitor";

    public async Task<IReadOnlyList<TokenMonitorInfo>> ListAsync(Guid tenantId, Guid projectId, CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);

        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var tokens = await db.SoftwareClientTokens.AsNoTracking()
            .Where(t => t.TenantId == tenantId && t.ProjectId == projectId)
            .Select(t => new { t.Id, t.LastAccessAt })
            .ToListAsync(ct)
            .ConfigureAwait(false);
        var tokenIds = tokens.Select(t => t.Id).ToList();
        var lastAccessByToken = tokens.ToDictionary(t => t.Id, t => t.LastAccessAt);

        var monitors = await db.TokenAccessMonitors.AsNoTracking()
            .Where(m => tokenIds.Contains(m.TokenId))
            .ToListAsync(ct)
            .ConfigureAwait(false);

        var zone = options.Value.ResolveTimeZone();
        return monitors
            .Select(m => new TokenMonitorInfo(
                m.TokenId,
                m.Enabled,
                m.MaxSilenceMinutes,
                m.WatchDaysMask,
                m.WatchStart,
                m.WatchEnd,
                m.NotifyOnRecovery,
                m.SnoozeUntil,
                m.State,
                m.LastStateChangeAt,
                m.Enabled
                    ? WatchWindowCalculator.NextDeadline(
                        lastAccessByToken.GetValueOrDefault(m.TokenId) ?? m.CreatedAt,
                        TimeSpan.FromMinutes(m.MaxSilenceMinutes),
                        m.WatchDaysMask, m.WatchStart, m.WatchEnd, zone)
                    : null))
            .ToList();
    }

    public async Task UpsertAsync(UpsertTokenMonitorCommand cmd, CancellationToken ct = default)
    {
        EnsureTenantScope(cmd.TenantId);
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        await EnsureSoftwareOperatorAsync(db, cmd.TenantId, cmd.ActorUserId, ct).ConfigureAwait(false);
        await EnsureTokenInTenantAsync(db, cmd.TenantId, cmd.TokenId, ct).ConfigureAwait(false);

        var monitor = await db.TokenAccessMonitors
            .FirstOrDefaultAsync(m => m.TokenId == cmd.TokenId, ct)
            .ConfigureAwait(false);

        if (monitor is null)
        {
            monitor = new TokenAccessMonitor(
                Guid.NewGuid(), cmd.TenantId, cmd.TokenId,
                cmd.MaxSilenceMinutes, cmd.WatchDaysMask, cmd.WatchStart, cmd.WatchEnd,
                cmd.NotifyOnRecovery, clock.UtcNow);
            db.TokenAccessMonitors.Add(monitor);
            await audit.AppendAsync(db, new AuditRequest(cmd.TenantId, AuditAction.Create, ResourceType, monitor.Id, cmd.ActorUserId), ct).ConfigureAwait(false);
        }
        else
        {
            monitor.SetSchedule(cmd.MaxSilenceMinutes, cmd.WatchDaysMask, cmd.WatchStart, cmd.WatchEnd);
            monitor.SetNotifyOnRecovery(cmd.NotifyOnRecovery);
            monitor.SetEnabled(true);
            await audit.AppendAsync(db, new AuditRequest(cmd.TenantId, AuditAction.Update, ResourceType, monitor.Id, cmd.ActorUserId), ct).ConfigureAwait(false);
        }

        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public async Task SnoozeAsync(Guid tenantId, Guid tokenId, DateTimeOffset? until, Guid? actorUserId, CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        await EnsureSoftwareOperatorAsync(db, tenantId, actorUserId, ct).ConfigureAwait(false);

        var monitor = await FindAsync(db, tenantId, tokenId, ct).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"No monitor exists for token {tokenId}.");

        if (until is { } instant)
        {
            if (instant <= clock.UtcNow)
            {
                throw new ArgumentException("The snooze end must lie in the future.", nameof(until));
            }

            monitor.Snooze(instant);
        }
        else
        {
            monitor.ClearSnooze();
        }

        await audit.AppendAsync(db, new AuditRequest(tenantId, AuditAction.Update, ResourceType, monitor.Id, actorUserId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public async Task SetEnabledAsync(Guid tenantId, Guid tokenId, bool enabled, Guid? actorUserId, CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        await EnsureSoftwareOperatorAsync(db, tenantId, actorUserId, ct).ConfigureAwait(false);

        var monitor = await FindAsync(db, tenantId, tokenId, ct).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"No monitor exists for token {tokenId}.");

        monitor.SetEnabled(enabled);
        await audit.AppendAsync(db, new AuditRequest(tenantId, AuditAction.Update, ResourceType, monitor.Id, actorUserId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    private static Task<TokenAccessMonitor?> FindAsync(KeywardDbContext db, Guid tenantId, Guid tokenId, CancellationToken ct) =>
        db.TokenAccessMonitors.FirstOrDefaultAsync(m => m.TokenId == tokenId && m.TenantId == tenantId, ct);

    /// <summary>The monitor's token must belong to the caller's tenant (installation-global table, so checked explicitly).</summary>
    private static async Task EnsureTokenInTenantAsync(KeywardDbContext db, Guid tenantId, Guid tokenId, CancellationToken ct)
    {
        var exists = await db.SoftwareClientTokens
            .AnyAsync(t => t.Id == tokenId && t.TenantId == tenantId, ct)
            .ConfigureAwait(false);
        if (!exists)
        {
            throw new InvalidOperationException($"Token {tokenId} not found.");
        }
    }

    // Same operator predicate as token/application management: system admin, software manager or tenant admin.
    private static async Task EnsureSoftwareOperatorAsync(KeywardDbContext db, Guid tenantId, Guid? actorUserId, CancellationToken ct)
    {
        if (actorUserId is not { } actor)
        {
            return; // trusted/system caller — the management API authorizes at the HTTP layer
        }

        var isOperator = await db.Users.AnyAsync(u => u.Id == actor && (u.IsSystemAdmin || u.IsSoftwareManager), ct).ConfigureAwait(false)
            || await db.TenantMemberships.AnyAsync(
                m => m.TenantId == tenantId && m.UserId == actor && m.Role == TenantRole.TenantAdmin, ct).ConfigureAwait(false);
        if (!isOperator)
        {
            throw new UnauthorizedAccessException("Managing heartbeat monitoring requires the tenant-admin or software-manager role.");
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
