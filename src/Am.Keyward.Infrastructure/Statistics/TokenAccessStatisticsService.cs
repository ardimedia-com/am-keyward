using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Am.Keyward.Infrastructure.Statistics;

/// <summary>
/// Read side of the per-application statistics UI. The statistics tables are installation-global (see the
/// flush service), so every query goes through the application's token set — which IS tenant-checked: the
/// requested tenant must match the server-authoritative scope, exactly like the token service.
/// </summary>
public sealed class TokenAccessStatisticsService(IDbContextFactory<KeywardDbContext> dbFactory, ICurrentTenant tenant, IClock clock) : ITokenAccessStatisticsService
{
    public async Task<IReadOnlyList<TokenDailyAccessInfo>> ListDailyAsync(Guid tenantId, Guid projectId, int days, CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var since = DateOnly.FromDateTime(clock.UtcNow.UtcDateTime).AddDays(-Math.Max(days, 1) + 1);
        var tokenIds = TokenIds(db, tenantId, projectId);
        return await db.TokenDailyAccesses.AsNoTracking()
            .Where(d => tokenIds.Contains(d.TokenId) && d.Date >= since)
            .OrderBy(d => d.Date)
            .Select(d => new TokenDailyAccessInfo(d.TokenId, d.Date, d.RequestCount))
            .ToListAsync(ct)
            .ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<TokenAccessIpInfo>> ListIpsAsync(Guid tenantId, Guid projectId, CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var tokenIds = TokenIds(db, tenantId, projectId);
        return await db.TokenAccessIps.AsNoTracking()
            .Where(i => tokenIds.Contains(i.TokenId))
            .OrderByDescending(i => i.LastSeenAt)
            .Select(i => new TokenAccessIpInfo(i.TokenId, i.IpAddress, i.FirstSeenAt, i.LastSeenAt))
            .ToListAsync(ct)
            .ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<TokenAccessAlertInfo>> ListAlertsAsync(Guid tenantId, Guid projectId, int take = 50, CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var tokenIds = TokenIds(db, tenantId, projectId);
        return await db.TokenAccessAlerts.AsNoTracking()
            .Where(a => tokenIds.Contains(a.TokenId))
            .OrderByDescending(a => a.CreatedAt)
            .Take(Math.Clamp(take, 1, 200))
            .Select(a => new TokenAccessAlertInfo(a.TokenId, a.Kind, a.IpAddress, a.CreatedAt))
            .ToListAsync(ct)
            .ConfigureAwait(false);
    }

    private static IQueryable<Guid> TokenIds(KeywardDbContext db, Guid tenantId, Guid projectId) =>
        db.SoftwareClientTokens.Where(t => t.TenantId == tenantId && t.ProjectId == projectId).Select(t => t.Id);

    private void EnsureTenantScope(Guid requestedTenantId)
    {
        if (tenant.TenantId != requestedTenantId)
        {
            throw new UnauthorizedAccessException(
                "Tenant scope mismatch: the request's tenant does not match the authenticated scope.");
        }
    }
}
