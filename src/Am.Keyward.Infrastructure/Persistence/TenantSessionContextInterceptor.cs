using System.Data.Common;
using Am.Keyward.Core.Abstractions;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace Am.Keyward.Infrastructure.Persistence;

/// <summary>
/// Stamps the SQL Server SESSION_CONTEXT keys <c>TenantId</c> and <c>UserId</c> on every opened connection
/// from the ambient tenant/user, so the database row-level-security policy enforces isolation independently
/// of (and as a backstop to) the application query filter. <c>TenantId</c> scopes tenant-owned rows;
/// <c>UserId</c> scopes tenant-less personal-vault rows. SESSION_CONTEXT is connection-scoped and cleared
/// when a pooled connection is reset on return, so it is (re)applied on each open, and set
/// <c>@read_only=1</c> so application code cannot change it for the life of the connection.
/// </summary>
public sealed class TenantSessionContextInterceptor(ICurrentTenant tenant, ICurrentUser user) : DbConnectionInterceptor
{
    private const string SetSessionContextSql =
        "EXEC sp_set_session_context @key = N'TenantId', @value = @tenant, @read_only = 1;" +
        "EXEC sp_set_session_context @key = N'UserId', @value = @user, @read_only = 1;";

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
        AddParameter(command, "@tenant", tenant.TenantId);
        AddParameter(command, "@user", user.UserId);
        return command;
    }

    private static void AddParameter(DbCommand command, string name, Guid? value)
    {
        var parameter = command.CreateParameter();
        parameter.ParameterName = name;
        parameter.Value = (object?)value ?? DBNull.Value;
        command.Parameters.Add(parameter);
    }
}
