namespace Am.Keyward.Contracts;

/// <summary>
/// Wire-level defaults shared by the server (endpoint mapping) and the client (request paths), so both
/// sides agree on the same values without either referencing the other.
/// </summary>
public static class KeywardApiDefaults
{
    /// <summary>
    /// Default base path the APIs are mapped at (<c>MapKeywardApi</c> / <c>MapKeywardClientApi</c>) and the
    /// client requests against. A host that maps the API elsewhere passes its own prefix on both sides.
    /// </summary>
    public const string BasePath = "/keyward/api/v1";
}
