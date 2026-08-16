using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Am.Keyward.Infrastructure.Crypto;

/// <summary>
/// Runs the key-ownership check once, during host start.
///
/// <para>Deliberately an <see cref="IHostedService"/> doing its work in <c>StartAsync</c> rather than a
/// <c>BackgroundService</c>: the host awaits it before the server accepts the first request, so the verdict
/// is in place before anything can read or write a secret. It never throws — a database that is unreachable
/// at this moment leaves the verdict <see cref="KekIntegrityStatus.Unknown"/>, which does not block; only a
/// CONFIRMED conflict does.</para>
/// </summary>
public sealed class KekIntegrityStartupCheck(
    IServiceScopeFactory scopeFactory,
    KeywardKeyIntegrityState state,
    ILogger<KekIntegrityStartupCheck> logger) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        try
        {
            using IServiceScope scope = scopeFactory.CreateScope();
            KekCanaryService canary = scope.ServiceProvider.GetRequiredService<KekCanaryService>();

            string writtenBy = $"{Environment.MachineName} ({Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT") ?? "unknown"})";
            (KekIntegrityStatus status, string? detail) = await canary.VerifyOrCreateAsync(writtenBy, cancellationToken).ConfigureAwait(false);
            state.Record(status, detail);

            switch (status)
            {
                case KekIntegrityStatus.Ok:
                    logger.LogInformation("KEYWARD: the key-encryption key owns this database (canary verified).");
                    break;

                case KekIntegrityStatus.Created:
                    logger.LogInformation("KEYWARD: key-ownership canary written. {Detail}", detail);
                    break;

                case KekIntegrityStatus.Conflict when state.IsBlocked:
                    logger.LogCritical(
                        "KEYWARD: KEY MISMATCH — encryption and decryption are DISABLED to keep the split from "
                        + "growing. {Detail}", detail);
                    break;

                case KekIntegrityStatus.Conflict:
                    logger.LogCritical(
                        "KEYWARD: KEY MISMATCH — configured to continue anyway (Keyward:KeyIntegrity:OnConflict=Warn). "
                        + "Every value written from now on will be unreadable to the installation that owns the data. "
                        + "{Detail}", detail);
                    break;
            }
        }
        catch (Exception ex)
        {
            state.Record(KekIntegrityStatus.Unknown, ex.Message);
            logger.LogError(ex,
                "KEYWARD: the key-ownership check could not run — continuing without a verdict. A key mismatch "
                + "would therefore not be caught this run.");
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
