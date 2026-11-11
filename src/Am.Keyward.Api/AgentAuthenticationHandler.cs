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
/// Authentication for AI agents: a Bearer agent token is validated by <see cref="IAgentAuthenticationValidator"/> on every
/// request. On success the request runs <b>as the token's user</b>: tenant, user and actor scope are set here,
/// directly — not through middleware order — so every Keyward service sees the user and every audit entry is
/// attributed to <see cref="ActorKind.Agent"/> with the token. A refused token is audited by the validator (when its
/// prefix identified a token) and counted by <see cref="FailedAuthenticationThrottle"/> per (address, prefix) — a token
/// that validates is never refused by the throttle. Every successful authentication records the token's last use
/// through <see cref="IAgentTokenAccessRecorder"/>.
/// </summary>
public sealed class AgentAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public const string SchemeName = "Keyward.Agent";

    public const string TokenIdClaim = "keyward:agent_token_id";
    public const string TenantIdClaim = "keyward:tenant_id";
    public const string ScopesClaim = "keyward:agent_scopes";

    private const string BearerPrefix = "Bearer ";

    private readonly IAgentAuthenticationValidator authenticator;
    private readonly ITenantScopeSetter tenantScope;
    private readonly IUserScopeSetter userScope;
    private readonly IActorScopeSetter actorScope;
    private readonly FailedAuthenticationThrottle failedAttempts;
    private readonly AgentNetworkPolicy networkPolicy;
    private readonly IAgentTokenAccessRecorder accessRecorder;

    // Marks a request refused for its network, so the challenge answers 403 instead of 401.
    private const string OutsideAllowedNetworks = "Keyward.Agent.OutsideAllowedNetworks";

    public AgentAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        IAgentAuthenticationValidator authenticator,
        ITenantScopeSetter tenantScope,
        IUserScopeSetter userScope,
        IActorScopeSetter actorScope,
        FailedAuthenticationThrottle failedAttempts,
        AgentNetworkPolicy networkPolicy,
        IAgentTokenAccessRecorder accessRecorder)
        : base(options, logger, encoder)
    {
        this.accessRecorder = accessRecorder;
        this.networkPolicy = networkPolicy;
        this.authenticator = authenticator;
        this.tenantScope = tenantScope;
        this.userScope = userScope;
        this.actorScope = actorScope;
        this.failedAttempts = failedAttempts;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var clientAddress = Context.Connection.RemoteIpAddress;

        // The host-wide network restriction comes first — before the header is even looked at: from elsewhere every
        // request is refused with 403 (with or without a token), no token is looked up, and the attempt does not
        // count against the failed-authentication throttle. An unusable setting refuses everyone (fail closed).
        if (!networkPolicy.Allows(clientAddress))
        {
            Context.Items[OutsideAllowedNetworks] = true;
            return AuthenticateResult.Fail("The agent API is not available from this network.");
        }

        if (!Request.Headers.TryGetValue("Authorization", out var header))
        {
            return AuthenticateResult.NoResult();
        }

        var raw = header.ToString();
        if (!raw.StartsWith(BearerPrefix, StringComparison.OrdinalIgnoreCase))
        {
            return AuthenticateResult.NoResult();
        }

        var clientIp = clientAddress?.ToString();
        var token = raw[BearerPrefix.Length..].Trim();
        var attempt = failedAttempts.TryBegin(clientIp, token);
        if (attempt is null)
        {
            Logger.LogDebug("KEYWARD: agent token refused without lookup — too many failed attempts for its prefix from {ClientIp}.", clientIp);
            return AuthenticateResult.Fail("Too many failed authentication attempts; try again later.");
        }

        TokenAuthenticationResult<AgentPrincipal> result;
        try
        {
            result = await authenticator.ValidateAsync(token, clientAddress, Context.RequestAborted);
        }
        catch
        {
            attempt.Abandoned();
            throw;
        }

        if (result.Principal is not { } principal)
        {
            if (attempt.Failed())
            {
                Logger.LogWarning(
                    "KEYWARD: {ClientIp} used up its failed agent-token authentications for one token prefix; that prefix is refused from there for the rest of the window.",
                    clientIp);
            }

            return AuthenticateResult.Fail("Invalid, expired or revoked agent token.");
        }

        attempt.Succeeded();
        tenantScope.SetTenant(principal.TenantId);
        userScope.SetUser(principal.UserId);
        actorScope.SetActor(ActorKind.Agent, principal.TokenId);

        // Last use (time + client address) is a security signal shown in the token list; in memory only, never throws.
        accessRecorder.Record(principal.TokenId, clientIp);

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
