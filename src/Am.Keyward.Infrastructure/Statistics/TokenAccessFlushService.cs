using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Domain.Software;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Am.Keyward.Infrastructure.Statistics;

/// <summary>
/// Persists the <see cref="TokenAccessAccumulator"/> batch on an interval: last access (+ IP) onto the
/// token record, per-day counters, the seen-IP set — and derives the rule-based access-pattern alerts
/// (new IP, resumed after silence) while it has both the previous and the fresh state in hand. Also
/// upserts the <see cref="SecretReadAccumulator"/> batch (last read + count per secret/environment; those
/// rows are never retention-trimmed — the long-term "is this secret still used?" signal). Once a day it
/// trims counters/IPs/alerts past the retention window. Best-effort: failures are logged and never
/// crash the host; a failed flush loses that interval's numbers, never the secret reads themselves. The
/// statistics tables are installation-global (like the token table), so this runs without a tenant scope.
/// </summary>
public sealed class TokenAccessFlushService(
    TokenAccessAccumulator accumulator,
    SecretReadAccumulator secretReads,
    IServiceScopeFactory scopeFactory,
    IClock clock,
    IOptions<TokenAccessOptions> options,
    ILogger<TokenAccessFlushService> logger) : BackgroundService
{
    private static readonly TimeSpan MinFlushInterval = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan CleanupInterval = TimeSpan.FromHours(24);

    private DateTimeOffset lastCleanupAt = DateTimeOffset.MinValue;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!options.Value.Enabled)
        {
            logger.LogInformation("Token access statistics are disabled ({Section}:Enabled = false).", TokenAccessOptions.SectionName);
            return;
        }

        var interval = TimeSpan.FromSeconds(Math.Max(options.Value.FlushIntervalSeconds, (int)MinFlushInterval.TotalSeconds));
        try
        {
            using var timer = new PeriodicTimer(interval);
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
            {
                try
                {
                    await FlushAsync(stoppingToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Token access statistics flush failed; the interval's numbers are lost, the next flush continues.");
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Host shutting down — expected. A final best-effort flush preserves the last interval.
            try
            {
                await FlushAsync(CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Final token access statistics flush on shutdown failed.");
            }
        }
    }

    private async Task FlushAsync(CancellationToken ct)
    {
        var batch = accumulator.Drain();
        var secretBatch = secretReads.Drain();
        var now = clock.UtcNow;
        var cleanupDue = now - lastCleanupAt >= CleanupInterval;
        if (batch.Count == 0 && secretBatch.Count == 0 && !cleanupDue)
        {
            return;
        }

        using var scope = scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();

        foreach (var (tokenId, access) in batch)
        {
            await PersistTokenBatchAsync(db, tokenId, access, ct).ConfigureAwait(false);
        }

        var scopeSetter = scope.ServiceProvider.GetRequiredService<ITenantScopeSetter>();
        foreach (var ((secretId, environmentId), read) in secretBatch)
        {
            await PersistSecretReadBatchAsync(db, scopeSetter, secretId, environmentId, read, ct).ConfigureAwait(false);
        }

        if (batch.Count > 0 || secretBatch.Count > 0)
        {
            await db.SaveChangesAsync(ct).ConfigureAwait(false);
        }

        if (cleanupDue)
        {
            await CleanupAsync(db, now, ct).ConfigureAwait(false);
            lastCleanupAt = now;
        }
    }

    private async Task PersistTokenBatchAsync(KeywardDbContext db, Guid tokenId, PendingTokenAccess access, CancellationToken ct)
    {
        var token = await db.SoftwareClientTokens.FirstOrDefaultAsync(t => t.Id == tokenId, ct).ConfigureAwait(false);
        if (token is null)
        {
            return; // deleted between access and flush
        }

        // Silence gap: compare the batch's FIRST access against the token's previous last access — while
        // both are still in hand, before the update overwrites the previous value.
        var silenceThreshold = TimeSpan.FromDays(Math.Max(options.Value.SilenceAlertDays, 1));
        if (token.LastAccessAt is { } previous && access.FirstAccessAt - previous >= silenceThreshold)
        {
            db.TokenAccessAlerts.Add(new TokenAccessAlert(
                Guid.NewGuid(), token.TenantId, token.Id, TokenAccessAlertKind.ResumedAfterSilence, access.LastIp, access.FirstAccessAt));
        }

        token.RecordAccess(access.LastAccessAt, access.LastIp);

        foreach (var (day, count) in access.CountsByDay)
        {
            var daily = await db.TokenDailyAccesses
                .FirstOrDefaultAsync(d => d.TokenId == token.Id && d.Date == day, ct)
                .ConfigureAwait(false);
            if (daily is null)
            {
                db.TokenDailyAccesses.Add(new TokenDailyAccess(Guid.NewGuid(), token.TenantId, token.Id, day, count));
            }
            else
            {
                daily.Add(count);
            }
        }

        if (access.IpLastSeen.Count > 0)
        {
            var knownIps = await db.TokenAccessIps
                .Where(i => i.TokenId == token.Id)
                .ToListAsync(ct)
                .ConfigureAwait(false);
            var hadKnownIps = knownIps.Count > 0;

            foreach (var (ip, lastSeen) in access.IpLastSeen)
            {
                var known = knownIps.FirstOrDefault(k => string.Equals(k.IpAddress, ip, StringComparison.OrdinalIgnoreCase));
                if (known is not null)
                {
                    known.Touch(lastSeen);
                    continue;
                }

                db.TokenAccessIps.Add(new TokenAccessIp(Guid.NewGuid(), token.TenantId, token.Id, ip, lastSeen, lastSeen));

                // A token's very first IP is baseline, not an anomaly — alert only once a baseline exists.
                if (hadKnownIps)
                {
                    db.TokenAccessAlerts.Add(new TokenAccessAlert(
                        Guid.NewGuid(), token.TenantId, token.Id, TokenAccessAlertKind.NewIpAddress, ip, lastSeen));
                }
            }
        }
    }

    private static async Task PersistSecretReadBatchAsync(
        KeywardDbContext db, ITenantScopeSetter scopeSetter, Guid secretId, Guid environmentId, PendingSecretRead read, CancellationToken ct)
    {
        var row = await db.SecretReadAccesses
            .FirstOrDefaultAsync(r => r.SoftwareSecretId == secretId && r.EnvironmentId == environmentId, ct)
            .ConfigureAwait(false);
        if (row is not null)
        {
            row.RecordRead(read.LastReadAt, read.LastSource, read.Count);
            return;
        }

        // The secret may have been deleted between read and flush — inserting then would violate the FK.
        // SoftwareSecrets is tenant-scoped (query filter + row-level security), and this job runs outside
        // any tenant scope — set the row's tenant for the check (the OpsMonitor pattern), or RLS would hide
        // an existing secret and the row would silently never be written.
        scopeSetter.SetTenant(read.TenantId);
        if (!await db.SoftwareSecrets.IgnoreQueryFilters().AnyAsync(s => s.Id == secretId, ct).ConfigureAwait(false))
        {
            return;
        }

        db.SecretReadAccesses.Add(new SecretReadAccess(
            Guid.NewGuid(), read.TenantId, secretId, environmentId, read.LastReadAt, read.LastSource, read.Count));
    }

    private async Task CleanupAsync(KeywardDbContext db, DateTimeOffset now, CancellationToken ct)
    {
        var retention = TimeSpan.FromDays(Math.Max(options.Value.RetentionDays, 1));
        var cutoff = now - retention;
        var cutoffDay = DateOnly.FromDateTime(cutoff.UtcDateTime);

        var days = await db.TokenDailyAccesses.Where(d => d.Date < cutoffDay).ExecuteDeleteAsync(ct).ConfigureAwait(false);
        var ips = await db.TokenAccessIps.Where(i => i.LastSeenAt < cutoff).ExecuteDeleteAsync(ct).ConfigureAwait(false);
        var alerts = await db.TokenAccessAlerts.Where(a => a.CreatedAt < cutoff).ExecuteDeleteAsync(ct).ConfigureAwait(false);
        if (days + ips + alerts > 0)
        {
            logger.LogInformation(
                "Token access statistics retention ({RetentionDays} days) removed {DayRows} daily counter(s), {IpRows} IP row(s), {AlertRows} alert(s).",
                options.Value.RetentionDays, days, ips, alerts);
        }
    }
}
