using System.Net;
using System.Security.Cryptography;
using System.Text;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Am.Keyward.Infrastructure.Auth;

/// <summary>
/// Authenticates a presented agent token on every request: prefix lookup, constant-time hash compare, then the
/// checks a signed-in session would get from the host — the user still exists, is not disabled and is still a
/// member of the token's tenant — and the caller's network. A refusal of a token the prefix identified is audited in
/// the token's tenant (<see cref="TokenAuthenticationAuditor"/>).
/// </summary>
public sealed class AgentAuthenticator(
    IDbContextFactory<KeywardDbContext> dbFactory,
    IClock clock,
    TokenAuthenticationAuditor auditor) : IAgentAuthenticator, IAgentAuthenticationValidator
{
    public async Task<AgentPrincipal?> AuthenticateAsync(string presentedToken, IPAddress? clientIp, CancellationToken ct = default) =>
        (await ValidateAsync(presentedToken, clientIp, ct).ConfigureAwait(false)).Principal;

    public async Task<TokenAuthenticationResult<AgentPrincipal>> ValidateAsync(string presentedToken, IPAddress? clientIp, CancellationToken ct = default)
    {
        var result = await CheckAsync(presentedToken, clientIp, ct).ConfigureAwait(false);
        if (!result.Succeeded)
        {
            await auditor.RecordRefusalAsync(ActorKind.Agent, result.Failure!.Value, result.TokenId, result.TenantId, clientIp, ct)
                .ConfigureAwait(false);
        }

        return result;
    }

    private async Task<TokenAuthenticationResult<AgentPrincipal>> CheckAsync(string presentedToken, IPAddress? clientIp, CancellationToken ct)
    {
        if (!SoftwareClientTokenGenerator.TryParsePrefix(presentedToken, AgentTokenService.Scheme, out var prefix))
        {
            return TokenAuthenticationResult<AgentPrincipal>.Refused(TokenAuthenticationFailure.Malformed);
        }

        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);

        // Installation-global table, read before the tenant is known.
        var candidate = await db.AgentTokens.AsNoTracking()
            .IgnoreQueryFilters()
            .FirstOrDefaultAsync(t => t.TokenPrefix == prefix, ct)
            .ConfigureAwait(false);

        if (candidate is null)
        {
            return TokenAuthenticationResult<AgentPrincipal>.Refused(TokenAuthenticationFailure.UnknownToken);
        }

        // The secret is compared BEFORE the state is reported: whoever does not hold the token learns nothing about it.
        var matches = CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(SoftwareClientTokenGenerator.Hash(presentedToken)),
            Encoding.ASCII.GetBytes(candidate.TokenHash));
        if (!matches)
        {
            return Refused(TokenAuthenticationFailure.WrongSecret);
        }

        if (!candidate.IsActive(clock.UtcNow))
        {
            return Refused(candidate.RevokedAt is not null ? TokenAuthenticationFailure.Revoked : TokenAuthenticationFailure.Expired);
        }

        var user = await db.Users.AsNoTracking()
            .Where(u => u.Id == candidate.UserId)
            .Select(u => new { u.IsSystemAdmin, u.DisabledAt })
            .FirstOrDefaultAsync(ct)
            .ConfigureAwait(false);
        if (user is null || user.DisabledAt is not null)
        {
            return Refused(TokenAuthenticationFailure.UserDisabled);
        }

        var isMember = user.IsSystemAdmin
            || await db.TenantMemberships.AsNoTracking()
                .AnyAsync(m => m.TenantId == candidate.TenantId && m.UserId == candidate.UserId, ct)
                .ConfigureAwait(false);
        if (!isMember)
        {
            return Refused(TokenAuthenticationFailure.NotTenantMember);
        }

        if (!IsFromAllowedNetwork(candidate.AllowedNetworks, clientIp))
        {
            return Refused(TokenAuthenticationFailure.NetworkRefused);
        }

        return TokenAuthenticationResult<AgentPrincipal>.Success(
            new AgentPrincipal(candidate.Id, candidate.TenantId, candidate.UserId, candidate.Scopes), candidate.Id, candidate.TenantId);

        TokenAuthenticationResult<AgentPrincipal> Refused(TokenAuthenticationFailure failure) =>
            TokenAuthenticationResult<AgentPrincipal>.Refused(failure, candidate.Id, candidate.TenantId);
    }

    internal static bool IsFromAllowedNetwork(string allowedNetworks, IPAddress? clientIp)
    {
        if (string.IsNullOrWhiteSpace(allowedNetworks))
        {
            return true;
        }

        if (clientIp is null)
        {
            return false;
        }

        // A dual-stack socket reports an IPv4 client as IPv4-mapped IPv6 (::ffff:10.0.0.5).
        var ip = clientIp.IsIPv4MappedToIPv6 ? clientIp.MapToIPv4() : clientIp;
        return allowedNetworks
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Any(n => IPNetwork.TryParse(n, out var network) && network.Contains(ip));
    }
}
