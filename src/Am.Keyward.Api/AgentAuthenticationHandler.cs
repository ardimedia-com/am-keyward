using System.Security.Claims;
using System.Text.Encodings.Web;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Am.Keyward.Api;

/// <summary>
/// Authentication for AI agents: a Bearer agent token is validated by <see cref="IAgentAuthenticator"/> on every
/// request. On success the request runs <b>as the token's user</b>: tenant, user and actor scope are set here,
/// directly — not through middleware order — so every Keyward service sees the user and every audit entry is
/// attributed to <see cref="ActorKind.Agent"/> with the token.
/// </summary>
public sealed class AgentAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public const string SchemeName = "Keyward.Agent";

    public const string TokenIdClaim = "keyward:agent_token_id";
    public const string TenantIdClaim = "keyward:tenant_id";
    public const string ScopesClaim = "keyward:agent_scopes";

    private const string BearerPrefix = "Bearer ";

    private readonly IAgentAuthenticator authenticator;
    private readonly ITenantScopeSetter tenantScope;
    private readonly IUserScopeSetter userScope;
    private readonly IActorScopeSetter actorScope;
    private readonly FailedAuthenticationThrottle failedAttempts;
    private readonly AgentNetworkPolicy networkPolicy;

    // Marks a request refused for its network, so the challenge answers 403 instead of 401.
    private const string OutsideAllowedNetworks = "Keyward.Agent.OutsideAllowedNetworks";

    public AgentAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        IAgentAuthenticator authenticator,
        ITenantScopeSetter tenantScope,
        IUserScopeSetter userScope,
        IActorScopeSetter actorScope,
        FailedAuthenticationThrottle failedAttempts,
        AgentNetworkPolicy networkPolicy)
        : base(options, logger, encoder)
    {
        this.networkPolicy = networkPolicy;
        this.authenticator = authenticator;
        this.tenantScope = tenantScope;
        this.userScope = userScope;
        this.actorScope = actorScope;
        this.failedAttempts = failedAttempts;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue("Authorization", out var header))
        {
            return AuthenticateResult.NoResult();
        }

        var raw = header.ToString();
        if (!raw.StartsWith(BearerPrefix, StringComparison.OrdinalIgnoreCase))
        {
            return AuthenticateResult.NoResult();
        }

        var clientAddress = Context.Connection.RemoteIpAddress;

        // The host-wide network restriction comes first: from elsewhere no token is looked up at all, and the
        // attempt does not count against the failed-authentication throttle.
        if (!networkPolicy.Allows(clientAddress))
        {
            Context.Items[OutsideAllowedNetworks] = true;
            return AuthenticateResult.Fail("The agent API is not available from this network.");
        }

        var clientIp = clientAddress?.ToString();
        if (failedAttempts.IsBlocked(clientIp))
        {
            return AuthenticateResult.Fail("Too many failed authentication attempts; try again later.");
        }

        var principal = await authenticator.AuthenticateAsync(raw[BearerPrefix.Length..].Trim(), clientAddress, Context.RequestAborted);
        if (principal is null)
        {
            failedAttempts.RecordFailure(clientIp);
            return AuthenticateResult.Fail("Invalid, expired or revoked agent token.");
        }

        tenantScope.SetTenant(principal.TenantId);
        userScope.SetUser(principal.UserId);
        actorScope.SetActor(ActorKind.Agent, principal.TokenId);

        var identity = new ClaimsIdentity(
        [
            new Claim(TokenIdClaim, principal.TokenId.ToString()),
            new Claim(TenantIdClaim, principal.TenantId.ToString()),
            new Claim(ScopesClaim, principal.Scopes.ToString()),
        ], SchemeName);

        return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName));
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        if (Context.Items.ContainsKey(OutsideAllowedNetworks))
        {
            Response.StatusCode = Microsoft.AspNetCore.Http.StatusCodes.Status403Forbidden;
            return Task.CompletedTask;
        }

        return base.HandleChallengeAsync(properties);
    }
}
