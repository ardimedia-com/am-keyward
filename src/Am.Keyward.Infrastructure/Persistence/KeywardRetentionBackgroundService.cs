using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Domain;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Am.Keyward.Infrastructure.Persistence;

/// <summary>Retention periods (section <see cref="SectionName"/>; all optional, safe defaults).</summary>
public sealed class KeywardRetentionOptions
{
    public const string SectionName = "Keyward:Retention";

    /// <summary>Kill-switch for the retention job.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// How long the personal vaults of a deleted account are kept before they are removed for good (feature.md,
    /// «Policies»: 90 days). Floored at 1.
    /// </summary>
    public int PersonalVaultRetentionDays { get; set; } = 90;

    /// <summary>How long decided, consumed or expired reveal requests are kept (days, floored at 1).</summary>
    public int RevealRequestRetentionDays { get; set; } = 30;
}

/// <summary>
/// The daily retention job:
/// <list type="bullet">
/// <item>removes the PERSONAL vaults (folders, items, every version) of accounts deleted through
/// <see cref="IKeywardAccountDeletion"/> more than <see cref="KeywardRetentionOptions.PersonalVaultRetentionDays"/> ago
/// and still deleted — conservative reading of feature.md: only an explicit deletion starts the clock, never a plain
/// disable (a disabled user may come back), and enabling the user again cancels it. Team vaults belong to the tenant
/// and are never touched. Each removal is audited on the personal chain as a system action;</item>
/// <item>purges reveal requests older than <see cref="KeywardRetentionOptions.RevealRequestRetentionDays"/> (they are
/// decided or expired within minutes; the audit chain keeps their history).</item>
/// </list>
/// Best-effort: failures are logged, never crash the host, and are retried on the next run. Runs once per
/// installation (see <see cref="KeywardInstanceLease"/>).
/// </summary>
public sealed class KeywardRetentionBackgroundService(
    IServiceScopeFactory scopeFactory,
    IClock clock,
    IOptions<KeywardRetentionOptions> options,
    ILogger<KeywardRetentionBackgroundService> logger) : BackgroundService
{
    private static readonly TimeSpan StartupDelay = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan CheckInterval = TimeSpan.FromHours(24);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!options.Value.Enabled)
        {
            logger.LogInformation("Keyward retention is disabled ({Section}:Enabled = false).", KeywardRetentionOptions.SectionName);
            return;
        }

        try
        {
            await Task.Delay(StartupDelay, stoppingToken).ConfigureAwait(false);
            using var timer = new PeriodicTimer(CheckInterval);
            do
            {
                try
                {
                    await RunOnceAsync(stoppingToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Keyward retention run failed; it is retried on the next run.");
                }
            }
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
            // Host shutting down — expected.
        }
    }

    /// <summary>One retention run. Returns how many personal vaults and reveal requests were removed.</summary>
    internal async Task<(int PersonalVaults, int RevealRequests)> RunOnceAsync(CancellationToken ct)
    {
        var now = clock.UtcNow;
        var vaults = await PurgePersonalVaultsAsync(now, ct).ConfigureAwait(false);
        var requests = await PurgeRevealRequestsAsync(now, ct).ConfigureAwait(false);
        if (vaults + requests > 0)
        {
            logger.LogInformation(
                "Keyward retention removed {VaultCount} personal vault(s) of deleted accounts and {RequestCount} old reveal request(s).",
                vaults, requests);
        }

        return (vaults, requests);
    }

    private async Task<int> PurgePersonalVaultsAsync(DateTimeOffset now, CancellationToken ct)
    {
        var cutoff = now - TimeSpan.FromDays(Math.Max(options.Value.PersonalVaultRetentionDays, 1));

        // Users are installation-global: discovery needs no scope.
        List<Guid> userIds;
        using (var discovery = scopeFactory.CreateScope())
        {
            var db = discovery.ServiceProvider.GetRequiredService<KeywardDbContext>();
            userIds = await db.Users.AsNoTracking()
                .Where(u => u.DeletedAt != null && u.DeletedAt <= cutoff && u.DisabledAt != null)
                .Select(u => u.Id)
                .ToListAsync(ct)
                .ConfigureAwait(false);
        }

        var removed = 0;
        foreach (var userId in userIds)
        {
            try
            {
                removed += await PurgeUserVaultsAsync(userId, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Removing the personal vaults of deleted user {UserId} failed; continuing with the next.", userId);
            }
        }

        return removed;
    }

    // Personal vaults are isolated per owner (query filter + row-level security on the session user), so the removal
    // runs in that user's scope. Folders, items, versions, agent allowances and reveal requests cascade in the database.
    private async Task<int> PurgeUserVaultsAsync(Guid userId, CancellationToken ct)
    {
        using var scope = scopeFactory.CreateScope();
        scope.ServiceProvider.GetRequiredService<IUserScopeSetter>().SetUser(userId);
        var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
        var audit = scope.ServiceProvider.GetRequiredService<DbAuditSink>();

        var vaults = await db.Vaults
            .Where(v => v.TenantId == null && v.OwnerUserId == userId)
            .ToListAsync(ct)
            .ConfigureAwait(false);
        if (vaults.Count == 0)
        {
            return 0;
        }

        foreach (var vault in vaults)
        {
            db.Vaults.Remove(vault);
            await audit.AppendAsync(db, new AuditRequest(null, AuditAction.Delete, "Vault", vault.Id, null, "Retention after account deletion"), ct).ConfigureAwait(false);
        }

        await db.SaveChangesAsync(ct).ConfigureAwait(false);
        return vaults.Count;
    }

    private async Task<int> PurgeRevealRequestsAsync(DateTimeOffset now, CancellationToken ct)
    {
        var cutoff = now - TimeSpan.FromDays(Math.Max(options.Value.RevealRequestRetentionDays, 1));

        // Reveal requests are tenant data (query filter + row-level security), so the purge runs per tenant. Every
        // request belongs to an agent token (cascade), and the token table is installation-global — it lists the
        // tenants that can have any.
        List<Guid> tenantIds;
        using (var discovery = scopeFactory.CreateScope())
        {
            var db = discovery.ServiceProvider.GetRequiredService<KeywardDbContext>();
            tenantIds = await db.AgentTokens.AsNoTracking().Select(t => t.TenantId).Distinct().ToListAsync(ct).ConfigureAwait(false);
        }

        var removed = 0;
        foreach (var tenantId in tenantIds)
        {
            using var scope = scopeFactory.CreateScope();
            scope.ServiceProvider.GetRequiredService<ITenantScopeSetter>().SetTenant(tenantId);
            var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();

            // A request is decided or expired within minutes (RevealRequestLifetime); anything this old is history,
            // whatever its stored status says.
            removed += await db.RevealRequests
                .Where(r => r.CreatedAt < cutoff)
                .ExecuteDeleteAsync(ct)
                .ConfigureAwait(false);
        }

        return removed;
    }
}
