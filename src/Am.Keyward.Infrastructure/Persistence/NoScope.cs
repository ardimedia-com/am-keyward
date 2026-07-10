using Am.Keyward.Core.Abstractions;

namespace Am.Keyward.Infrastructure.Persistence;

/// <summary>
/// A no-tenant/no-user scope for building the <see cref="KeywardDbContext"/> model outside a request —
/// design-time tooling (<see cref="KeywardDbContextFactory"/>) and startup schema migration
/// (<see cref="KeywardSchemaMigrator"/>). Migrations and model building run no tenant-scoped queries, so
/// there is nothing to scope.
/// </summary>
internal sealed class NoScope : ICurrentTenant, ICurrentUser
{
    public static readonly NoScope Instance = new();

    public Guid? TenantId => null;

    public Guid? UserId => null;

    public bool IsAuthenticated => false;
}
