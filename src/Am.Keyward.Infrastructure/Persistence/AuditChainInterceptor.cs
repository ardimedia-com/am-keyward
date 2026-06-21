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
    private const string LockResource = "Keyward_AuditChain";

    // Mirrors TenantSessionContextInterceptor: opening the connection ourselves bypasses EF's
    // ConnectionOpened interceptor, so we must set the row-level-security session context here too.
    private const string SetSessionContextSql =
        "EXEC sp_set_session_context @key = N'TenantId', @value = @tenant, @read_only = 1;" +
        "EXEC sp_set_session_context @key = N'UserId', @value = @user, @read_only = 1;";

    private DbConnection? _connectionOpenedHere;
    private bool _lockHeld;

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

        await ExecuteAsync(connection,
            $"EXEC sp_getapplock @Resource = N'{LockResource}', @LockMode = 'Exclusive', @LockOwner = 'Session';", ct)
            .ConfigureAwait(false);
        _lockHeld = true;

        foreach (var group in pending.GroupBy(e => e.TenantId))
        {
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
        if (!_lockHeld && _connectionOpenedHere is null)
        {
            return;
        }

        var connection = context?.Database.GetDbConnection();
        if (_lockHeld && connection is { State: ConnectionState.Open })
        {
            try
            {
                await ExecuteAsync(connection, $"EXEC sp_releaseapplock @Resource = N'{LockResource}', @LockOwner = 'Session';", ct).ConfigureAwait(false);
            }
            catch
            {
                // Best-effort: closing the connection (or session end) releases a session-scoped lock anyway.
            }
        }

        _lockHeld = false;

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
