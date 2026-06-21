using Am.Keyward.Core.Abstractions;
using Microsoft.AspNetCore.Http;

namespace Am.Keyward.Ui.Blazor.App.Identity;

/// <summary>
/// Resolves the current Keyward user from the authenticated principal's <c>keyward:user_id</c> claim
/// (stamped into the cookie by <see cref="KeywardUserClaimsPrincipalFactory"/>). Available on HTTP
/// requests (the API and Blazor static rendering); in an interactive circuit, where there is no
/// HttpContext, components pass the acting user explicitly and authorization is enforced by tenant scope.
/// </summary>
public sealed class HttpContextCurrentUser(IHttpContextAccessor accessor) : ICurrentUser
{
    public Guid? UserId =>
        Guid.TryParse(
            accessor.HttpContext?.User.FindFirst(KeywardUserClaimsPrincipalFactory.UserIdClaim)?.Value,
            out var id)
            ? id
            : null;

    public bool IsAuthenticated => accessor.HttpContext?.User.Identity?.IsAuthenticated ?? false;
}
