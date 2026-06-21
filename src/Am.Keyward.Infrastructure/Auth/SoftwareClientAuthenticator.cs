using System.Security.Cryptography;
using System.Text;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Am.Keyward.Infrastructure.Auth;

/// <summary>
/// Authenticates a presented software-client token: parse its prefix, look up the (installation-global)
/// token record by that prefix, then constant-time compare the full-token hash and check it is active. On
/// success it returns the token's (tenant, project, environment) scope.
/// </summary>
public sealed class SoftwareClientAuthenticator(KeywardDbContext db, IClock clock) : ISoftwareClientAuthenticator
{
    public async Task<SoftwareClientPrincipal?> AuthenticateAsync(string presentedToken, CancellationToken ct = default)
    {
        if (!SoftwareClientTokenGenerator.TryParsePrefix(presentedToken, out var prefix))
        {
            return null;
        }

        // The token table is installation-global (not tenant-scoped): it must be read before the tenant is
        // known. IgnoreQueryFilters is defensive in case a filter is ever added.
        var candidate = await db.SoftwareClientTokens
            .IgnoreQueryFilters()
            .FirstOrDefaultAsync(t => t.TokenPrefix == prefix, ct)
            .ConfigureAwait(false);

        if (candidate is null || !candidate.IsActive(clock.UtcNow))
        {
            return null;
        }

        var presentedHash = SoftwareClientTokenGenerator.Hash(presentedToken);
        var matches = CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(presentedHash),
            Encoding.ASCII.GetBytes(candidate.TokenHash));

        return matches
            ? new SoftwareClientPrincipal(candidate.Id, candidate.TenantId, candidate.ProjectId, candidate.EnvironmentId)
            : null;
    }
}
