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
/// Authentication for software clients: a Bearer token in the <c>Authorization</c> header is validated by
/// <see cref="ISoftwareClientAuthenticator"/>. On success the request's tenant scope is set
/// server-authoritatively from the token (so the query filter and row-level security apply) and the
/// token's (tenant, project, environment) scope is exposed as claims for the endpoints to read. The client
/// never supplies tenant/project/environment — those come only from the token record.
/// </summary>
public sealed class SoftwareClientAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public const string SchemeName = "Keyward.SoftwareClient";

    public const string TokenIdClaim = "keyward:token_id";
    public const string TenantIdClaim = "keyward:tenant_id";
    public const string ProjectIdClaim = "keyward:project_id";
    public const string EnvironmentIdClaim = "keyward:environment_id";

    private const string BearerPrefix = "Bearer ";

    private readonly ISoftwareClientAuthenticator authenticator;
    private readonly ITenantScopeSetter tenantScope;
    private readonly IActorScopeSetter actorScope;
    private readonly ITokenAccessRecorder accessRecorder;
    private readonly FailedAuthenticationThrottle failedAttempts;

    public SoftwareClientAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISoftwareClientAuthenticator authenticator,
        ITenantScopeSetter tenantScope,
        IActorScopeSetter actorScope,
        ITokenAccessRecorder accessRecorder,
        FailedAuthenticationThrottle failedAttempts)
        : base(options, logger, encoder)
    {
        this.authenticator = authenticator;
        this.tenantScope = tenantScope;
        this.actorScope = actorScope;
        this.accessRecorder = accessRecorder;
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

        // An IP that has used up its failed attempts is refused before the token lookup, so guessing tokens
        // costs the attacker time and the database nothing. A valid token from that IP waits out the window too.
        var clientIp = Context.Connection.RemoteIpAddress?.ToString();
        if (failedAttempts.IsBlocked(clientIp))
        {
            return AuthenticateResult.Fail("Too many failed authentication attempts; try again later.");
        }

        var token = raw[BearerPrefix.Length..].Trim();
        var principal = await authenticator.AuthenticateAsync(token, Context.RequestAborted);
        if (principal is null)
        {
            failedAttempts.RecordFailure(clientIp);
            return AuthenticateResult.Fail("Invalid or expired software-client token.");
        }

        // Server-authoritative tenant scope, from the token record (never from the request).
        tenantScope.SetTenant(principal.TenantId);

        // Audit attribution: what this request does is recorded as the software client, with its token.
        actorScope.SetActor(ActorKind.SoftwareClient, principal.TokenId);

        // Access statistics (last access, daily counters, seen IPs → alerts): purely in-memory here,
        // persisted by the background flush — never a database write on the auth hot path. The IP is the
        // connection's remote address; behind a proxy/load balancer it is only meaningful when the host
        // has forwarded-headers middleware configured.
        accessRecorder.Record(principal.TokenId, clientIp);

        var identity = new ClaimsIdentity(
        [
            new Claim(TokenIdClaim, principal.TokenId.ToString()),
            new Claim(TenantIdClaim, principal.TenantId.ToString()),
            new Claim(ProjectIdClaim, principal.ProjectId.ToString()),
            new Claim(EnvironmentIdClaim, principal.EnvironmentId.ToString()),
        ], SchemeName);

        var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName);
        return AuthenticateResult.Success(ticket);
    }
}
