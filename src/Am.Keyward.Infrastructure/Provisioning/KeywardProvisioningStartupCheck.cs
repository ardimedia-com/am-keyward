using Am.Keyward.Core.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Am.Keyward.Infrastructure.Provisioning;

/// <summary>
/// One-shot startup diagnostic. Shortly after boot — when Keyward is enabled but not fully provisioned in
/// THIS environment — it logs the exact remaining points, so a half-configured environment is visible in the
/// operator's log (and in whatever run-report the host mails) without anyone opening a status page.
/// <para>
/// Runs OFF the critical startup path (a short delay, in a background service) so a slow or failing database
/// probe never delays or crashes boot, and it runs exactly ONCE — it is a provisioning check, not a monitor.
/// </para>
/// <para>
/// Log messages are English (they go to shared log infrastructure); the same checks rendered for a human in
/// their own language are the UI's job.
/// </para>
/// </summary>
public sealed class KeywardProvisioningStartupCheck(
    IServiceScopeFactory scopeFactory,
    ILogger<KeywardProvisioningStartupCheck> logger) : BackgroundService
{
    /// <summary>Lets the startup schema migration + tenant seed run first, and keeps the probe off the boot path.</summary>
    private static readonly TimeSpan StartupDelay = TimeSpan.FromSeconds(10);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await Task.Delay(StartupDelay, stoppingToken).ConfigureAwait(false);

            using IServiceScope scope = scopeFactory.CreateScope();
            KeywardProvisioningStatusService status =
                scope.ServiceProvider.GetRequiredService<KeywardProvisioningStatusService>();

            if (!status.Enabled && status.Expectation != KeywardExpectation.Required)
            {
                // Off where that is fine — nothing to report.
                return;
            }

            IReadOnlyList<KeywardCheck> checks = await status.RunAsync(stoppingToken).ConfigureAwait(false);
            if (checks.AllOk())
            {
                logger.LogInformation("AM KEYWARD is enabled and fully provisioned in {Environment}.", status.EnvironmentName);
                return;
            }

            List<KeywardCheck> gaps = [.. checks.Where(c => c.State != KeywardCheckState.Ok)];
            string details = string.Join(
                "\n",
                gaps.Select(c => $"  - {c.Id}: {KeywardProvisioningText.Describe(c)}"
                    + (c.Technical is { Length: > 0 } technical ? $" [{technical}]" : string.Empty)
                    + (c.Error is { Length: > 0 } error ? $" ({error})" : string.Empty)));

            logger.LogWarning(
                "AM KEYWARD is enabled in {Environment} but {Count} provisioning check(s) are not green — Keyward is "
                + "unavailable until these are resolved:\n{Details}",
                status.EnvironmentName, gaps.Count, details);
        }
        catch (OperationCanceledException)
        {
            // Host shutting down — expected.
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "AM KEYWARD startup provisioning check could not run.");
        }
    }
}

/// <summary>
/// English one-liners for the log. The UI renders the same outcomes in the viewer's language from the
/// package's resources; this exists because log output is English by convention and must not depend on
/// whatever culture a background thread happens to carry.
/// </summary>
public static class KeywardProvisioningText
{
    /// <summary>A short English description of why a check came out as it did.</summary>
    public static string Describe(KeywardCheck check) => check.Outcome switch
    {
        KeywardCheckOutcome.Ok => "ok",
        KeywardCheckOutcome.FeatureOffAcceptable => "switched off (acceptable in this environment)",
        KeywardCheckOutcome.FeatureOffRequired => "switched off although this environment requires Keyward",
        KeywardCheckOutcome.KekMissing => "the key file does not exist yet; it is created on the next start — back it up offline afterwards",
        KeywardCheckOutcome.KekNotFileBased => "an external key provider is configured; no key file to check",
        KeywardCheckOutcome.ConnectionMissing => "no connection string configured",
        KeywardCheckOutcome.ConnectionUnreadable => "the connection string cannot be parsed",
        KeywardCheckOutcome.ConnectionIntegratedSecurityOutsideDevelopment =>
            "configured with Integrated Security; outside Development the least-privilege login is expected",
        KeywardCheckOutcome.DatabaseUnreachable => "the connection could not be opened",
        KeywardCheckOutcome.SchemaMissing => "the amkeyward schema does not exist in this database",
        KeywardCheckOutcome.SchemaNoMigrations => "the schema exists but no migration has been applied",
        KeywardCheckOutcome.SchemaUnreadable => "the migration state could not be read (check the login's rights)",
        KeywardCheckOutcome.TenantMissing => "the tenant has not been seeded",
        KeywardCheckOutcome.TenantUnreadable => "the tenant row could not be read (check the login's rights)",
        _ => "not probed, because an earlier prerequisite is missing",
    };
}
