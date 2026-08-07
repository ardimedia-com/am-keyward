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
/// <para>
/// A null tenant/user is expressed by LEAVING THE KEY UNSET, never by writing NULL — see
/// <see cref="SessionContextCommand"/> for why (SQL Server bug KB4089324, error 15665).
/// </para>
/// </summary>
public sealed class TenantSessionContextInterceptor(ICurrentTenant tenant, ICurrentUser user, SystemReadScope systemRead) : DbConnectionInterceptor
{
    public override void ConnectionOpened(DbConnection connection, ConnectionEndEventData eventData)
    {
        using var command = connection.CreateCommand();
        if (SessionContextCommand.TryPrepare(command, tenant.TenantId, user.UserId, systemRead.Enabled))
        {
            command.ExecuteNonQuery();
        }
    }

    public override async Task ConnectionOpenedAsync(
        DbConnection connection, ConnectionEndEventData eventData, CancellationToken cancellationToken = default)
    {
        await using var command = connection.CreateCommand();
        if (SessionContextCommand.TryPrepare(command, tenant.TenantId, user.UserId, systemRead.Enabled))
        {
            await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
    }
}
