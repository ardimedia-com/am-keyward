using System.Net;
using System.Security.Cryptography;
using System.Text;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Am.Keyward.Infrastructure.Auth;

/// <summary>
/// Authenticates a presented agent token on every request: prefix lookup, constant-time hash compare, then the
/// checks a signed-in session would get from the host — the user still exists, is not disabled and is still a
/// member of the token's tenant — and the caller's network.
/// </summary>
public sealed class AgentAuthenticator(IDbContextFactory<KeywardDbContext> dbFactory, IClock clock) : IAgentAuthenticator
{
    public async Task<AgentPrincipal?> AuthenticateAsync(string presentedToken, IPAddress? clientIp, CancellationToken ct = default)
    {
        if (!SoftwareClientTokenGenerator.TryParsePrefix(presentedToken, AgentTokenService.Scheme, out var prefix))
        {
            return null;
        }

        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);

        // Installation-global table, read before the tenant is known.
        var candidate = await db.AgentTokens.AsNoTracking()
            .IgnoreQueryFilters()
            .FirstOrDefaultAsync(t => t.TokenPrefix == prefix, ct)
            .ConfigureAwait(false);

        if (candidate is null || !candidate.IsActive(clock.UtcNow))
        {
            return null;
        }

        var matches = CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(SoftwareClientTokenGenerator.Hash(presentedToken)),
            Encoding.ASCII.GetBytes(candidate.TokenHash));
        if (!matches)
        {
            return null;
        }

        var user = await db.Users.AsNoTracking()
            .Where(u => u.Id == candidate.UserId)
            .Select(u => new { u.IsSystemAdmin, u.DisabledAt })
            .FirstOrDefaultAsync(ct)
            .ConfigureAwait(false);
        if (user is null || user.DisabledAt is not null)
        {
            return null;
        }

        var isMember = user.IsSystemAdmin
            || await db.TenantMemberships.AsNoTracking()
                .AnyAsync(m => m.TenantId == candidate.TenantId && m.UserId == candidate.UserId, ct)
                .ConfigureAwait(false);
        if (!isMember || !IsFromAllowedNetwork(candidate.AllowedNetworks, clientIp))
        {
            return null;
        }

        return new AgentPrincipal(candidate.Id, candidate.TenantId, candidate.UserId, candidate.Scopes);
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
