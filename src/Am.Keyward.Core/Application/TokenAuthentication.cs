using System.Net;

namespace Am.Keyward.Core.Application;

/// <summary>Why a presented agent or software-client token was refused.</summary>
public enum TokenAuthenticationFailure
{
    /// <summary>Not a Keyward token of the expected kind at all (no lookup was made).</summary>
    Malformed,

    /// <summary>No token with the presented prefix exists.</summary>
    UnknownToken,

    /// <summary>The prefix names a token, but the secret does not match it.</summary>
    WrongSecret,

    /// <summary>An app token that has not been minted yet (pending placeholder).</summary>
    Pending,

    /// <summary>The token's validity ended.</summary>
    Expired,

    /// <summary>The token was revoked.</summary>
    Revoked,

    /// <summary>The token's user no longer exists or is disabled.</summary>
    UserDisabled,

    /// <summary>The token's user is no longer a member of the token's tenant.</summary>
    NotTenantMember,

    /// <summary>The caller's address is outside the networks the token is restricted to.</summary>
    NetworkRefused,
}

/// <summary>
/// The detailed result of a token authentication: the principal on success, otherwise the reason and — when the
/// prefix identified a token record — that token and its tenant (so the refusal can be audited in the right chain).
/// Never carries the presented token.
/// </summary>
public sealed record TokenAuthenticationResult<TPrincipal>(
    TPrincipal? Principal,
    TokenAuthenticationFailure? Failure,
    Guid? TokenId,
    Guid? TenantId)
    where TPrincipal : class
{
    /// <summary>Whether the token validated.</summary>
    public bool Succeeded => Principal is not null;

    /// <summary>A validated token.</summary>
    public static TokenAuthenticationResult<TPrincipal> Success(TPrincipal principal, Guid tokenId, Guid tenantId) =>
        new(principal, null, tokenId, tenantId);

    /// <summary>A refused token; <paramref name="tokenId"/>/<paramref name="tenantId"/> only when a record was identified.</summary>
    public static TokenAuthenticationResult<TPrincipal> Refused(TokenAuthenticationFailure failure, Guid? tokenId = null, Guid? tenantId = null) =>
        new(null, failure, tokenId, tenantId);
}

/// <summary>
/// Detailed agent-token authentication (the reason of a refusal, for the audit trail and the failed-authentication
/// throttle). Implemented by the same authenticator as <see cref="IAgentAuthenticator"/>.
/// </summary>
public interface IAgentAuthenticationValidator
{
    Task<TokenAuthenticationResult<AgentPrincipal>> ValidateAsync(string presentedToken, IPAddress? clientIp, CancellationToken ct = default);
}

/// <summary>
/// Detailed software-client-token authentication (see <see cref="IAgentAuthenticationValidator"/>). Implemented by the
/// same authenticator as <see cref="ISoftwareClientAuthenticator"/>.
/// </summary>
public interface ISoftwareClientAuthenticationValidator
{
    Task<TokenAuthenticationResult<SoftwareClientPrincipal>> ValidateAsync(string presentedToken, IPAddress? clientIp, CancellationToken ct = default);
}
