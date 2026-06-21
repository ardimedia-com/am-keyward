using Am.Keyward.Core.Abstractions;

namespace Am.Keyward.Infrastructure.Tenancy;

/// <summary>
/// Placeholder current-user until authentication lands (software-client tokens and the human sign-in
/// flow are later slices). Reports an unauthenticated principal; the host replaces this registration
/// once a real identity is wired up.
/// </summary>
public sealed class AnonymousCurrentUser : ICurrentUser
{
    public Guid? UserId => null;

    public bool IsAuthenticated => false;
}
