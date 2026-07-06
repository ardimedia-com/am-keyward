using System.Data;
using System.Data.Common;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Domain.Audit;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace Am.Keyward.Infrastructure.Persistence;

/// <summary>
/// The single writer for the audit hash chain. At SaveChanges it assigns each pending
/// <see cref="AuditEntry"/> its per-tenant sequence number and chained hashes while holding a
/// session-scoped SQL Server application lock, so concurrent writers — even across instances — cannot fork
/// a tenant's chain or collide on its sequence. The lock is released after commit (or on failure).
/// Scoped per DbContext (a context is used sequentially), so the small amount of per-save state is safe.
/// </summary>
public sealed class AuditChainInterceptor(ICurrentTenant tenant, ICurrentUser user) : SaveChangesInterceptor
{
    // Per-tenant lock resource: appends for different tenants serialize on different locks and no longer
    // contend on one installation-wide lock. The tenant-less (personal/system) chain shares one resource.
    private static string LockResourceFor(Guid? tenantId) =>
        tenantId is { } t ? $"Keyward_AuditChain_{t:N}" : "Keyward_AuditChain_system";

    // Mirrors TenantSessionContextInterceptor: opening the connection ourselves bypasses EF's
    // ConnectionOpened interceptor, so we must set the row-level-security session context here too.
    private const string SetSessionContextSql =
        "EXEC sp_set_session_context @key = N'TenantId', @value = @tenant, @read_only = 1;" +
        "EXEC sp_set_session_context @key = N'UserId', @value = @user, @read_only = 1;";

    private DbConnection? _connectionOpenedHere;
    private readonly List<string> _heldLocks = [];

    public override async ValueTask<InterceptionResult<int>> SavingChangesAsync(
        DbContextEventData eventData, InterceptionResult<int> result, CancellationToken ct = default)
    {
        var context = eventData.Context;
        if (context is null)
        {
            return result;
        }

        var pending = context.ChangeTracker.Entries<AuditEntry>()
            .Where(e => e.State == EntityState.Added)
            .Select(e => e.Entity)
            .ToList();
        if (pending.Count == 0)
        {
            return result;
        }

        var connection = context.Database.GetDbConnection();
        if (connection.State != ConnectionState.Open)
        {
            await connection.OpenAsync(ct).ConfigureAwait(false);
            _connectionOpenedHere = connection;
            await SetSessionContextAsync(connection, ct).ConfigureAwait(false); // EF's interceptor didn't fire
        }

        // Read the chain head with the row-level-security READ bypass on: a group's tenant may differ from
        // the ambient session tenant (a null/personal chain written while a tenant is in scope, or a
        // cross-tenant break-glass entry), and RLS would otherwise hide those rows so the head read returns
        // nothing and the chain silently forks (re-sealing sequence 1). The bypass is confined to this head
        // read and only affects the FILTER predicate (reads); the audit INSERT that follows is unaffected.
        await SetBypassAsync(connection, on: true, ct).ConfigureAwait(false);
        try
        {
            // Order groups by tenant so a multi-tenant save always takes its per-tenant locks in the same
            // order across writers — no deadlock. Each group's lock is held until after commit (ReleaseAsync).
            foreach (var group in pending.GroupBy(e => e.TenantId).OrderBy(g => g.Key))
            {
                var resource = LockResourceFor(group.Key);
                await ExecuteAsync(connection,
                    $"EXEC sp_getapplock @Resource = N'{resource}', @LockMode = 'Exclusive', @LockOwner = 'Session';", ct)
                    .ConfigureAwait(false);
                _heldLocks.Add(resource);

                var (sequence, previousHash) = await ReadHeadAsync(connection, group.Key, ct).ConfigureAwait(false);
                foreach (var entry in group.OrderBy(e => e.OccurredAt))
                {
                    sequence++;
                    var hash = AuditChainHash.Compute(
                        entry.TenantId, sequence, entry.Action, entry.ResourceType,
                        entry.ResourceId, entry.ActorPseudonymId, entry.OccurredAt, previousHash);
                    entry.Seal(sequence, previousHash, hash);
                    previousHash = hash;
                }
            }
        }
        finally
        {
            await SetBypassAsync(connection, on: false, ct).ConfigureAwait(false);
        }

        return result;
    }

    public override async ValueTask<int> SavedChangesAsync(
        SaveChangesCompletedEventData eventData, int result, CancellationToken ct = default)
    {
        await ReleaseAsync(eventData.Context, ct).ConfigureAwait(false);
        return result;
    }

    public override async Task SaveChangesFailedAsync(DbContextErrorEventData eventData, CancellationToken ct = default)
    {
        await ReleaseAsync(eventData.Context, ct).ConfigureAwait(false);
    }

    private async Task ReleaseAsync(DbContext? context, CancellationToken ct)
    {
        if (_heldLocks.Count == 0 && _connectionOpenedHere is null)
        {
            return;
        }

        var connection = context?.Database.GetDbConnection();
        if (_heldLocks.Count > 0 && connection is { State: ConnectionState.Open })
        {
            foreach (var resource in _heldLocks)
            {
                try
                {
                    await ExecuteAsync(connection, $"EXEC sp_releaseapplock @Resource = N'{resource}', @LockOwner = 'Session';", ct).ConfigureAwait(false);
                }
                catch
                {
                    // Best-effort: closing the connection (or session end) releases a session-scoped lock anyway.
                }
            }
        }

        _heldLocks.Clear();

        if (_connectionOpenedHere is not null)
        {
            await _connectionOpenedHere.CloseAsync().ConfigureAwait(false);
            _connectionOpenedHere = null;
        }
    }

    private async Task SetSessionContextAsync(DbConnection connection, CancellationToken ct)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = SetSessionContextSql;
        AddParameter(command, "@tenant", tenant.TenantId);
        AddParameter(command, "@user", user.UserId);
        await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    private static async Task<(long Sequence, string PreviousHash)> ReadHeadAsync(DbConnection connection, Guid? tenantId, CancellationToken ct)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = tenantId is null
            ? "SELECT TOP 1 [Sequence], [Hash] FROM [amkeyward].[AuditEntries] WHERE [TenantId] IS NULL ORDER BY [Sequence] DESC;"
            : "SELECT TOP 1 [Sequence], [Hash] FROM [amkeyward].[AuditEntries] WHERE [TenantId] = @t ORDER BY [Sequence] DESC;";

        if (tenantId is not null)
        {
            AddParameter(command, "@t", tenantId.Value);
        }

        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        return await reader.ReadAsync(ct).ConfigureAwait(false)
            ? (reader.GetInt64(0), reader.GetString(1))
            : (0L, AuditChainHash.GenesisHash);
    }

    private static Task SetBypassAsync(DbConnection connection, bool on, CancellationToken ct) =>
        ExecuteAsync(connection, $"EXEC sp_set_session_context @key = N'SystemBypass', @value = {(on ? 1 : 0)};", ct);

    private static async Task ExecuteAsync(DbConnection connection, string sql, CancellationToken ct)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    private static void AddParameter(DbCommand command, string name, Guid? value)
    {
        var parameter = command.CreateParameter();
        parameter.ParameterName = name;
        parameter.Value = (object?)value ?? DBNull.Value;
        command.Parameters.Add(parameter);
    }
}
