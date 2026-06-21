using Am.Keyward.Core.Abstractions;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Am.Keyward.Infrastructure.Auth;

/// <summary>
/// Periodically surfaces software-client tokens that are nearing expiry, so operators can rotate them
/// before a fleet outage. v0.1 logs the due tokens (name + prefix + scope + days left — never the secret);
/// actual delivery (email/webhook) and per-window de-duplication are ops-hardening. Best-effort: failures
/// are logged and never crash the host. The token table is installation-global, so this runs without a
/// tenant scope.
/// </summary>
public sealed class SoftwareClientTokenExpiryService(
    IServiceScopeFactory scopeFactory,
    IClock clock,
    ILogger<SoftwareClientTokenExpiryService> logger) : BackgroundService
{
    private static readonly TimeSpan CheckInterval = TimeSpan.FromHours(24);
    private static readonly TimeSpan StartupDelay = TimeSpan.FromMinutes(1);
    private const int NoticeWindowDays = 30;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await Task.Delay(StartupDelay, stoppingToken).ConfigureAwait(false);
            using var timer = new PeriodicTimer(CheckInterval);
            do
            {
                await ReportExpiringTokensAsync(stoppingToken).ConfigureAwait(false);
            }
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
            // Host shutting down — expected.
        }
    }

    private async Task ReportExpiringTokensAsync(CancellationToken ct)
    {
        try
        {
            var now = clock.UtcNow;
            var horizon = now.AddDays(NoticeWindowDays);

            using var scope = scopeFactory.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();

            var due = await db.SoftwareClientTokens
                .Where(t => t.RevokedAt == null && t.ExpiresAt != null && t.ExpiresAt > now && t.ExpiresAt <= horizon)
                .Select(t => new { t.Name, t.TokenPrefix, t.ProjectId, t.EnvironmentId, t.ExpiresAt })
                .ToListAsync(ct)
                .ConfigureAwait(false);

            foreach (var token in due)
            {
                var daysLeft = (int)Math.Ceiling((token.ExpiresAt!.Value - now).TotalDays);
                logger.LogWarning(
                    "Software-client token '{TokenName}' ({TokenPrefix}) for project {ProjectId} environment {EnvironmentId} expires in {DaysLeft} day(s) on {ExpiresAt:u} — rotate it before then.",
                    token.Name, token.TokenPrefix, token.ProjectId, token.EnvironmentId, daysLeft, token.ExpiresAt);
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to check for expiring software-client tokens.");
        }
    }
}
