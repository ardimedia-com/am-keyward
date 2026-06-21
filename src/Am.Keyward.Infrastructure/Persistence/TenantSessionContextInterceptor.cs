using System.Data.Common;
using Am.Keyward.Core.Abstractions;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace Am.Keyward.Infrastructure.Persistence;

/// <summary>
/// Stamps the SQL Server SESSION_CONTEXT key <c>TenantId</c> on every opened connection from the ambient
/// tenant, so the database row-level-security policy enforces tenant isolation independently of (and as a
/// backstop to) the application query filter. SESSION_CONTEXT is connection-scoped and cleared when a
/// pooled connection is reset on return, so it is (re)applied on each open. It is set <c>@read_only=1</c>
/// so application code cannot change the tenant for the life of the connection.
/// </summary>
public sealed class TenantSessionContextInterceptor(ICurrentTenant tenant) : DbConnectionInterceptor
{
    private const string SetSessionContextSql =
        "EXEC sp_set_session_context @key = N'TenantId', @value = @tenant, @read_only = 1;";

    public override void ConnectionOpened(DbConnection connection, ConnectionEndEventData eventData)
    {
        using var command = CreateCommand(connection);
        command.ExecuteNonQuery();
    }

    public override async Task ConnectionOpenedAsync(
        DbConnection connection, ConnectionEndEventData eventData, CancellationToken cancellationToken = default)
    {
        await using var command = CreateCommand(connection);
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private DbCommand CreateCommand(DbConnection connection)
    {
        var command = connection.CreateCommand();
        command.CommandText = SetSessionContextSql;

        var parameter = command.CreateParameter();
        parameter.ParameterName = "@tenant";
        parameter.Value = (object?)tenant.TenantId ?? DBNull.Value;
        command.Parameters.Add(parameter);

        return command;
    }
}
