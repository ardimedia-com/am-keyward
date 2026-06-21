using Am.Keyward.Infrastructure.Persistence;
using Am.Keyward.Ui.Blazor.App.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Am.Keyward.Ui.Blazor.App.BackgroundServices;

/// <summary>
/// Runtime migration safety-net. The app migrates on startup, but if the database is swapped/refreshed
/// under the running instance (e.g. a nightly production copy into test), that startup migration is
/// bypassed and the app would fail at query time on a stale schema. This periodically re-checks both
/// contexts for pending migrations and applies them. EF Core serializes migrations across instances via
/// its own <c>__EFMigrationsLock</c>, so it is safe to run from every instance. Best-effort: failures are
/// logged and never crash the host. The cleanest fix remains operational — recycle the app whenever the
/// DB is swapped — and this is the in-app backstop for when that step cannot be controlled.
/// </summary>
public sealed class DatabaseMigrationBackgroundService(
    IServiceScopeFactory scopeFactory,
    IOptions<DatabaseMigrationOptions> options,
    ILogger<DatabaseMigrationBackgroundService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var settings = options.Value;
        if (!settings.Enabled)
        {
            logger.LogInformation("Runtime database-migration safety-net is disabled.");
            return;
        }

        var interval = TimeSpan.FromSeconds(Math.Max(10, settings.CheckIntervalSeconds));

        try
        {
            await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken).ConfigureAwait(false); // startup already migrated at t=0
            using var timer = new PeriodicTimer(interval);
            do
            {
                await CheckAsync(stoppingToken).ConfigureAwait(false);
            }
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
            // Host shutting down — expected.
        }
    }

    private async Task CheckAsync(CancellationToken ct)
    {
        using var scope = scopeFactory.CreateScope();
        await MigrateIfPendingAsync(scope.ServiceProvider.GetRequiredService<KeywardDbContext>(), "Keyward", ct).ConfigureAwait(false);
        await MigrateIfPendingAsync(scope.ServiceProvider.GetRequiredService<KeywardIdentityDbContext>(), "Identity", ct).ConfigureAwait(false);
    }

    private async Task MigrateIfPendingAsync(DbContext db, string name, CancellationToken ct)
    {
        try
        {
            var pending = (await db.Database.GetPendingMigrationsAsync(ct).ConfigureAwait(false)).ToList();
            if (pending.Count == 0)
            {
                return;
            }

            logger.LogWarning(
                "Applying {Count} pending {Context} migration(s) at runtime — the database appears to have changed under the running app.",
                pending.Count, name);
            await db.Database.MigrateAsync(ct).ConfigureAwait(false); // EF serializes via __EFMigrationsLock
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Runtime migration check for the {Context} context failed.", name);
        }
    }
}
