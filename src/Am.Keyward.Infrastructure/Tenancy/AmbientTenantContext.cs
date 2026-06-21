using Am.Keyward.Core.Abstractions;

namespace Am.Keyward.Infrastructure.Tenancy;

/// <summary>
/// Scoped holder of the current tenant. Implements both the read side (<see cref="ICurrentTenant"/>,
/// consumed by the DbContext query filter, the SQL Server SESSION_CONTEXT interceptor and the services)
/// and the write side (<see cref="ITenantScopeSetter"/>, called only at the host edge). One instance per
/// request/circuit, so setting it is isolated per caller.
/// </summary>
public sealed class AmbientTenantContext : ICurrentTenant, ITenantScopeSetter
{
    public Guid? TenantId { get; private set; }

    public void SetTenant(Guid? tenantId) => TenantId = tenantId;
}
