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
/// Authenticates a presented software-client token: parse its prefix, look up the (installation-global)
/// token record by that prefix, then constant-time compare the full-token hash and check it is active. On
/// success it returns the token's (tenant, project, environment) scope. A refusal of a token the prefix identified
/// (wrong secret, pending, expired, revoked) is audited in the token's tenant (<see cref="TokenAuthenticationAuditor"/>).
/// </summary>
public sealed class SoftwareClientAuthenticator(
    IDbContextFactory<KeywardDbContext> dbFactory,
    IClock clock,
    TokenAuthenticationAuditor auditor) : ISoftwareClientAuthenticator, ISoftwareClientAuthenticationValidator
{
    public async Task<SoftwareClientPrincipal?> AuthenticateAsync(string presentedToken, CancellationToken ct = default) =>
        (await ValidateAsync(presentedToken, clientIp: null, ct).ConfigureAwait(false)).Principal;

    public async Task<TokenAuthenticationResult<SoftwareClientPrincipal>> ValidateAsync(
        string presentedToken, IPAddress? clientIp, CancellationToken ct = default)
    {
        var result = await CheckAsync(presentedToken, ct).ConfigureAwait(false);
        if (!result.Succeeded)
        {
            await auditor.RecordRefusalAsync(ActorKind.SoftwareClient, result.Failure!.Value, result.TokenId, result.TenantId, clientIp, ct)
                .ConfigureAwait(false);
        }

        return result;
    }

    private async Task<TokenAuthenticationResult<SoftwareClientPrincipal>> CheckAsync(string presentedToken, CancellationToken ct)
    {
        if (!SoftwareClientTokenGenerator.TryParsePrefix(presentedToken, out var prefix))
        {
            return TokenAuthenticationResult<SoftwareClientPrincipal>.Refused(TokenAuthenticationFailure.Malformed);
        }

        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);

        // The token table is installation-global (not tenant-scoped): it must be read before the tenant is
        // known. IgnoreQueryFilters is defensive in case a filter is ever added. Untracked: this runs on every
        // client request, and nothing here is written back.
        var candidate = await db.SoftwareClientTokens
            .AsNoTracking()
            .IgnoreQueryFilters()
            .FirstOrDefaultAsync(t => t.TokenPrefix == prefix, ct)
            .ConfigureAwait(false);

        if (candidate is null)
        {
            return TokenAuthenticationResult<SoftwareClientPrincipal>.Refused(TokenAuthenticationFailure.UnknownToken);
        }

        // The secret is compared BEFORE the state is reported: whoever does not hold the token learns nothing about it.
        var presentedHash = SoftwareClientTokenGenerator.Hash(presentedToken);
        var matches = CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(presentedHash),
            Encoding.ASCII.GetBytes(candidate.TokenHash));
        if (!matches)
        {
            return TokenAuthenticationResult<SoftwareClientPrincipal>.Refused(TokenAuthenticationFailure.WrongSecret, candidate.Id, candidate.TenantId);
        }

        if (!candidate.IsActive(clock.UtcNow))
        {
            var failure = !candidate.HasSecret ? TokenAuthenticationFailure.Pending
                : candidate.RevokedAt is not null ? TokenAuthenticationFailure.Revoked
                : TokenAuthenticationFailure.Expired;
            return TokenAuthenticationResult<SoftwareClientPrincipal>.Refused(failure, candidate.Id, candidate.TenantId);
        }

        return TokenAuthenticationResult<SoftwareClientPrincipal>.Success(
            new SoftwareClientPrincipal(candidate.Id, candidate.TenantId, candidate.ProjectId, candidate.EnvironmentId, candidate.AuditReads),
            candidate.Id,
            candidate.TenantId);
    }
}
