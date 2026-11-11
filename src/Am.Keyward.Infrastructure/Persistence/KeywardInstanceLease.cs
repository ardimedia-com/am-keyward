using System.Data;
using Am.Keyward.Core.Abstractions;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Am.Keyward.Infrastructure.Persistence;

/// <summary>Whether this process holds the single-instance lease on its database.</summary>
public enum KeywardInstanceLeaseStatus
{
    /// <summary>Not checked yet, or the database was unreachable at the last attempt.</summary>
    Unknown,

    /// <summary>This process is the one AM KEYWARD instance on the database.</summary>
    Held,

    /// <summary>Another process holds the lease: a second instance runs against the same database — unsupported.</summary>
    HeldElsewhere,
}

/// <summary>The latest verdict of <see cref="KeywardInstanceLease"/>, read by the health check. Singleton, thread-safe.</summary>
public sealed class KeywardInstanceLeaseState
{
    private readonly Lock gate = new();

    public KeywardInstanceLeaseStatus Status { get; private set; } = KeywardInstanceLeaseStatus.Unknown;

    public DateTimeOffset? CheckedAt { get; private set; }

    public string? Detail { get; private set; }

    public void Record(KeywardInstanceLeaseStatus status, DateTimeOffset at, string? detail)
    {
        lock (gate)
        {
            Status = status;
            CheckedAt = at;
            Detail = detail;
        }
    }
}

/// <summary>
/// Detects a second AM KEYWARD instance on the same database. ONE instance per database is the supported deployment
/// (decision T1062 A): the background jobs — statistics flush, heartbeat evaluation, notification mails, retention —
/// assume they run once, and they are deliberately not locked across instances. Running two would double notices and
/// can lose statistics batches, so this service makes the mistake loud instead of silent.
/// <para>
/// How: at start (and every minute) the process takes a SESSION-scoped SQL Server application lock
/// (<c>sp_getapplock</c>, no wait) on a dedicated, non-pooled connection that stays open for the lifetime of the
/// process. A second process cannot get it: it logs an error, and <see cref="KeywardInstanceLeaseState"/> makes the
/// health check report Unhealthy. If the database restarts the lock goes with the session and is taken again on the
/// next check. Costs one idle connection; no table, no schema.
/// </para>
/// </summary>
public sealed class KeywardInstanceLease(
    IServiceScopeFactory scopeFactory,
    KeywardInstanceLeaseState state,
    IClock clock,
    ILogger<KeywardInstanceLease> logger) : BackgroundService
{
    /// <summary>The application-lock resource; app locks are per database, so this is «one instance per database».</summary>
    internal const string LockResource = "Keyward_SingleInstance";

    private static readonly TimeSpan CheckInterval = TimeSpan.FromMinutes(1);

    private SqlConnection? leaseConnection;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            using var timer = new PeriodicTimer(CheckInterval);
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
        finally
        {
            await ReleaseAsync().ConfigureAwait(false);
        }
    }

    /// <summary>One check: keeps a held lease alive, or tries to take it.</summary>
    internal async Task<KeywardInstanceLeaseStatus> CheckAsync(CancellationToken ct)
    {
        var previous = state.Status;
        try
        {
            if (leaseConnection is { State: ConnectionState.Open } && await StillHeldAsync(leaseConnection, ct).ConfigureAwait(false))
            {
                state.Record(KeywardInstanceLeaseStatus.Held, clock.UtcNow, null);
                return KeywardInstanceLeaseStatus.Held;
            }

            await ReleaseAsync().ConfigureAwait(false);
            var connection = new SqlConnection(await LeaseConnectionStringAsync(ct).ConfigureAwait(false));
            await connection.OpenAsync(ct).ConfigureAwait(false);
            if (await TryAcquireAsync(connection, ct).ConfigureAwait(false))
            {
                leaseConnection = connection;
                state.Record(KeywardInstanceLeaseStatus.Held, clock.UtcNow, null);
                if (previous == KeywardInstanceLeaseStatus.HeldElsewhere)
                {
                    logger.LogInformation("AM KEYWARD is now the only instance on its database; the single-instance lease is held.");
                }

                return KeywardInstanceLeaseStatus.Held;
            }

            await connection.DisposeAsync().ConfigureAwait(false);
            const string Detail = "Another AM KEYWARD instance is running against the same database.";
            state.Record(KeywardInstanceLeaseStatus.HeldElsewhere, clock.UtcNow, Detail);
            if (previous != KeywardInstanceLeaseStatus.HeldElsewhere)
            {
                logger.LogError(
                    "{Detail} Only ONE instance per database is supported: background jobs (notification mails, statistics "
                    + "flush, heartbeat monitoring, retention) are not coordinated across instances and would run twice. "
                    + "Stop the extra instance (check web farms, IIS web gardens, overlapping deployments and a second "
                    + "host process on the same database). This instance reports Unhealthy until it is the only one.",
                    Detail);
            }

            return KeywardInstanceLeaseStatus.HeldElsewhere;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            await ReleaseAsync().ConfigureAwait(false);
            state.Record(KeywardInstanceLeaseStatus.Unknown, clock.UtcNow, "The database was not reachable for the single-instance check.");
            if (previous != KeywardInstanceLeaseStatus.Unknown)
            {
                logger.LogWarning(ex, "Single-instance check failed; it is retried every {Interval}.", CheckInterval);
            }

            return KeywardInstanceLeaseStatus.Unknown;
        }
    }

    // The lease must live on its OWN physical connection: closing a pooled connection keeps its session — and the lock —
    // alive in the pool, so the lease could neither be released on shutdown nor be told apart from EF's connections.
    private async Task<string> LeaseConnectionStringAsync(CancellationToken ct)
    {
        using var scope = scopeFactory.CreateScope();
        var factory = scope.ServiceProvider.GetRequiredService<IDbContextFactory<KeywardDbContext>>();
        await using var db = await factory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var builder = new SqlConnectionStringBuilder(db.Database.GetConnectionString())
        {
            Pooling = false,
            ApplicationName = "AM KEYWARD instance lease",
        };
        return builder.ConnectionString;
    }

    private static async Task<bool> TryAcquireAsync(SqlConnection connection, CancellationToken ct)
    {
        await using var command = connection.CreateCommand();
        command.CommandText =
            "DECLARE @result int; "
            + "EXEC @result = sp_getapplock @Resource = @resource, @LockMode = 'Exclusive', @LockOwner = 'Session', @LockTimeout = 0; "
            + "SELECT @result;";
        command.Parameters.Add(new SqlParameter("@resource", SqlDbType.NVarChar, 255) { Value = LockResource });
        var result = Convert.ToInt32(await command.ExecuteScalarAsync(ct).ConfigureAwait(false), System.Globalization.CultureInfo.InvariantCulture);
        return result >= 0; // 0 granted, 1 granted after wait; -1 timeout (held elsewhere), below that an error
    }

    private static async Task<bool> StillHeldAsync(SqlConnection connection, CancellationToken ct)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT APPLOCK_MODE('public', @resource, 'Session');";
        command.Parameters.Add(new SqlParameter("@resource", SqlDbType.NVarChar, 255) { Value = LockResource });
        var mode = await command.ExecuteScalarAsync(ct).ConfigureAwait(false) as string;
        return string.Equals(mode, "Exclusive", StringComparison.OrdinalIgnoreCase);
    }

    // Disposing the non-pooled connection ends the session, and SQL Server releases the session lock with it.
    private async Task ReleaseAsync()
    {
        if (leaseConnection is { } connection)
        {
            leaseConnection = null;
            await connection.DisposeAsync().ConfigureAwait(false);
        }
    }

    public override void Dispose()
    {
        leaseConnection?.Dispose();
        leaseConnection = null;
        base.Dispose();
    }
}
