using Am.Keyward.Core.Abstractions;

namespace Am.Keyward.Infrastructure.Tenancy;

/// <summary>
/// Scoped holder of the current user. Read side (<see cref="ICurrentUser"/>) is consumed by the DbContext
/// query filter, the SQL Server SESSION_CONTEXT interceptor and the services; the write side
/// (<see cref="IUserScopeSetter"/>) is called only at the host edge (from the authenticated principal).
/// One instance per request/circuit. Defaults to unauthenticated until the edge sets a user.
/// </summary>
public sealed class AmbientUserContext : ICurrentUser, IUserScopeSetter
{
    public Guid? UserId { get; private set; }

    public bool IsAuthenticated => UserId is not null;

    public void SetUser(Guid? userId) => UserId = userId;
}
