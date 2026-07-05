using System.Data.Common;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Infrastructure.Tenancy;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace Am.Keyward.Infrastructure.Persistence;

/// <summary>
/// Stamps the SQL Server SESSION_CONTEXT keys <c>TenantId</c> and <c>UserId</c> on every opened connection
/// from the ambient tenant/user, so the database row-level-security policy enforces isolation independently
/// of (and as a backstop to) the application query filter. <c>TenantId</c> scopes tenant-owned rows;
/// <c>UserId</c> scopes tenant-less personal-vault rows. SESSION_CONTEXT is connection-scoped and cleared
/// when a pooled connection is reset on return, so it is (re)applied on each open, and set
/// <c>@read_only=1</c> so application code cannot change it for the life of the connection.
/// It also stamps <c>SystemBypass</c> from <see cref="SystemReadScope"/> — <c>1</c> only for the trusted,
/// tenant-less maintenance sweeps that must read across every tenant, otherwise <c>0</c> (full isolation).
/// The bypass is honored solely by the FILTER predicates of the audit / encrypted-version tables, never the
/// BLOCK predicates, so it can never enable a cross-tenant write.
/// </summary>
public sealed class TenantSessionContextInterceptor(ICurrentTenant tenant, ICurrentUser user, SystemReadScope systemRead) : DbConnectionInterceptor
{
    private const string SetSessionContextSql =
        "EXEC sp_set_session_context @key = N'TenantId', @value = @tenant, @read_only = 1;" +
        "EXEC sp_set_session_context @key = N'UserId', @value = @user, @read_only = 1;" +
        "EXEC sp_set_session_context @key = N'SystemBypass', @value = @bypass;";

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

        var bypass = command.CreateParameter();
        bypass.ParameterName = "@bypass";
        bypass.Value = systemRead.Enabled ? 1 : 0;
        command.Parameters.Add(bypass);
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
