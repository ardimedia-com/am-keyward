using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Domain.KeyCustody;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Am.Keyward.Infrastructure.Crypto;

/// <summary>
/// Runs the key-ownership check once, during host start, and registers this installation.
///
/// <para>Deliberately an <see cref="IHostedService"/> doing its work in <c>StartAsync</c> rather than a
/// <c>BackgroundService</c>: the host awaits it before the server accepts the first request, so the verdict
/// is in place before anything can read or write a secret. It never throws — a database that is unreachable
/// at this moment leaves the verdict <see cref="KekIntegrityStatus.Unknown"/>, which does not block; only a
/// CONFIRMED conflict does. An Unknown verdict is re-run later: lazily on the first use of the key and by the ops
/// monitor (<see cref="KeywardKeyIntegrityState.EnsureVerifiedAsync"/>, <see cref="KeywardKeyIntegrityState.RecheckAsync"/>).</para>
/// </summary>
public sealed class KekIntegrityStartupCheck(
    IServiceScopeFactory scopeFactory,
    KeywardKeyIntegrityState state,
    IOptions<KeywardKeyIntegrityOptions> options,
    ILogger<KekIntegrityStartupCheck> logger) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        try
        {
            // The verdict and its log lines come from the state, so a startup check and every later recheck say
            // the same thing in the same words. It never throws for an unreachable database.
            KekIntegrityStatus status = await state.RecheckAsync(cancellationToken).ConfigureAwait(false);
            if (status == KekIntegrityStatus.Unknown)
            {
                return;   // no database: nothing to register either
            }

            using IServiceScope scope = scopeFactory.CreateScope();
            KeywardInstallationRegistry registry = scope.ServiceProvider.GetRequiredService<KeywardInstallationRegistry>();
            IKekProvider kek = scope.ServiceProvider.GetRequiredService<IKekProvider>();
            await this.ReportPeersAsync(registry, kek.KekId, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            if (state.Status == KekIntegrityStatus.Unknown)
            {
                state.Record(KekIntegrityStatus.Unknown, ex.Message);
            }

            logger.LogError(ex,
                "KEYWARD: the key-ownership check could not run — continuing without a verdict. It is retried on the "
                + "next use of the key and by the ops monitor.");
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <summary>
    /// Registers this installation and says what else runs against the same database. Purely diagnostic: the
    /// canary has already decided whether the key may be used, this puts names to the situation — and in the
    /// healthy case makes a shared database visible as the deliberate arrangement it is. Best-effort, so a
    /// failure here never affects the verdict.
    /// </summary>
    private async Task ReportPeersAsync(KeywardInstallationRegistry registry, string currentKekId, CancellationToken ct)
    {
        try
        {
            IReadOnlyList<KeywardInstallation> peers = await registry.RecordAndListPeersAsync(ct).ConfigureAwait(false);
            if (peers.Count == 0)
            {
                return;
            }

            List<KeywardInstallation> foreignKey =
                [.. peers.Where(p => !string.Equals(p.KekId, currentKekId, StringComparison.Ordinal))];
            if (foreignKey.Count > 0)
            {
                // The canary blocked this already; what this adds is WHICH deployment is the other one.
                logger.LogCritical(
                    "KEYWARD: {Count} installation(s) write this database under a DIFFERENT key: {Peers}. One of "
                    + "them is pointed at the wrong database, or at the wrong key store.",
                    foreignKey.Count, string.Join("; ", foreignKey.Select(Describe)));
            }

            string? myLocation = options.Value.KeyCustodyLocation;
            if (!string.IsNullOrWhiteSpace(myLocation))
            {
                List<KeywardInstallation> divergentPath =
                [
                    .. peers.Where(p =>
                        string.Equals(p.KekId, currentKekId, StringComparison.Ordinal)
                        && string.Equals(p.MachineName, registry.Current.MachineName, StringComparison.OrdinalIgnoreCase)
                        && !string.IsNullOrWhiteSpace(p.KeyCustodyLocation)
                        && !string.Equals(p.KeyCustodyLocation, myLocation, StringComparison.OrdinalIgnoreCase))
                ];
                if (divergentPath.Count > 0)
                {
                    // Same machine, same key, two key files: it works today because the files happen to hold
                    // the same bytes, and stops working the moment one of them is rotated or restored.
                    logger.LogWarning(
                        "KEYWARD: installation(s) on this machine hold the same key at a DIFFERENT location than "
                        + "'{Mine}': {Peers}. Point them at one key file, or a rotation will split them.",
                        myLocation, string.Join("; ", divergentPath.Select(Describe)));
                }
            }

            logger.LogInformation(
                "KEYWARD: {Count} other installation(s) share this database: {Peers}.",
                peers.Count, string.Join("; ", peers.Select(Describe)));
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex,
                "KEYWARD: the installation registry could not be updated — diagnosis only, nothing else is affected.");
        }
    }

    private static string Describe(KeywardInstallation p) =>
        $"{p.EnvironmentName}@{p.MachineName} (key {p.KekId}, schema {p.SchemaVersion ?? "-"}, "
        + $"last seen {p.LastSeenAt:yyyy-MM-dd HH:mm})";
}
