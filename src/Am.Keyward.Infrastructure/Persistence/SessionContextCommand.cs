using System.Data.Common;
using System.Text;

namespace Am.Keyward.Infrastructure.Persistence;

/// <summary>
/// Builds the row-level-security SESSION_CONTEXT statement shared by
/// <see cref="TenantSessionContextInterceptor"/> (every opened connection) and
/// <see cref="AuditChainInterceptor"/> (which opens its own connection and so bypasses that interceptor).
/// <para>
/// A key whose value is <c>null</c> is <b>omitted</b> rather than set to NULL. That is not a cosmetic
/// choice: <c>SESSION_CONTEXT(N'…')</c> returns NULL for an unset key anyway, so the RLS predicates behave
/// identically — but repeatedly calling <c>sp_set_session_context</c> with a NULL value trips SQL Server
/// bug KB4089324, where the memory of the NULL write is never reclaimed. The session then accumulates
/// toward the 1 MB cap until every statement on that connection fails with error 15665 («The value was not
/// set for key 'TenantId' because the total size of keys and values in the session context would exceed the
/// 1 MB limit»). Because the leak lives on the pooled physical connection, a tenant-less caller (background
/// sweep, software-client token API — <see cref="Tenancy.AmbientTenantContext.TenantId"/> is null until the
/// host edge sets it) poisons the connection for whichever request draws it next.
/// </para>
/// <para>
/// The bug is fixed in SQL Server 2017 CU6 / 2016 SP1 CU8, but a server on the RTM-GDR branch (14.0.2xxx)
/// receives only security fixes and therefore never gets it — which is exactly how it surfaced in
/// production on 2026-08-07 while Test (2019 CU32) and Development (2025) were unaffected. Omitting the key
/// removes the trigger on every build, patched or not.
/// </para>
/// </summary>
internal static class SessionContextCommand
{
    /// <summary>
    /// Sets <paramref name="command"/>'s text and parameters for the non-null values among
    /// <paramref name="tenantId"/> / <paramref name="userId"/> / <paramref name="systemBypass"/>.
    /// Pass <c>null</c> for <paramref name="systemBypass"/> when the caller manages that key itself.
    /// </summary>
    /// <returns>
    /// <c>false</c> when there is nothing to set, so the caller can skip the round-trip entirely.
    /// </returns>
    public static bool TryPrepare(DbCommand command, Guid? tenantId, Guid? userId, bool? systemBypass)
    {
        ArgumentNullException.ThrowIfNull(command);

        var sql = new StringBuilder();

        if (tenantId is { } tenant)
        {
            sql.Append("EXEC sp_set_session_context @key = N'TenantId', @value = @tenant, @read_only = 1;");
            AddParameter(command, "@tenant", tenant);
        }

        if (userId is { } user)
        {
            sql.Append("EXEC sp_set_session_context @key = N'UserId', @value = @user, @read_only = 1;");
            AddParameter(command, "@user", user);
        }

        // SystemBypass is always 0 or 1 — never NULL, so it never hits the KB4089324 path. It is written
        // unconditionally (not only when enabled) so a stale 1 from an earlier caller on the same connection
        // can never survive into a session that must not bypass.
        if (systemBypass is { } bypass)
        {
            sql.Append("EXEC sp_set_session_context @key = N'SystemBypass', @value = @bypass;");
            var parameter = command.CreateParameter();
            parameter.ParameterName = "@bypass";
            parameter.Value = bypass ? 1 : 0;
            command.Parameters.Add(parameter);
        }

        command.CommandText = sql.ToString();
        return sql.Length > 0;
    }

    private static void AddParameter(DbCommand command, string name, Guid value)
    {
        var parameter = command.CreateParameter();
        parameter.ParameterName = name;
        parameter.Value = value;
        command.Parameters.Add(parameter);
    }
}
