namespace Am.Keyward.AspNetCore;

/// <summary>
/// The claim types AM KEYWARD's hosting glue reads from the authenticated principal to establish the
/// server-authoritative current user (and whether they are a system admin). The host's auth layer — ASP.NET
/// Core Identity, an external OIDC IdP, ... — is responsible for STAMPING these claims onto the principal;
/// this package only CONSUMES them (see <see cref="KeywardHostingExtensions"/>). Kept here, provider-agnostic,
/// so the claim producer and every consumer share one source of truth.
/// </summary>
public static class KeywardClaims
{
    /// <summary>The Keyward <c>AppUser</c> id (a GUID) of the signed-in user; drives personal-vault isolation.</summary>
    public const string UserId = "keyward:user_id";

    /// <summary>Present with value <c>"true"</c> when the signed-in user is a system admin.</summary>
    public const string SystemAdmin = "keyward:is_system_admin";
}
