using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Domain;

namespace Am.Keyward.Infrastructure.Tenancy;

/// <summary>
/// Scoped holder of the acting principal kind and token. Read side (<see cref="ICurrentActor"/>) is consumed by
/// the audit sink; the write side (<see cref="IActorScopeSetter"/>) is called only by the token authentication
/// handlers. One instance per request/circuit; unset until a handler sets it.
/// </summary>
public sealed class AmbientActorContext : ICurrentActor, IActorScopeSetter
{
    public ActorKind? Kind { get; private set; }

    public Guid? TokenId { get; private set; }

    public void SetActor(ActorKind kind, Guid? tokenId)
    {
        Kind = kind;
        TokenId = tokenId;
    }
}
