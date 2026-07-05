using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain.Software;
using Am.Keyward.Core.Domain.ValueObjects;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Am.Keyward.Infrastructure.Auth;

/// <summary>
/// Issues, rotates, revokes and lists software-client tokens. Issuance returns the plaintext token once;
/// only its hash is persisted. All operations are gated on the server-authoritative current tenant.
/// </summary>
public sealed class SoftwareClientTokenService(
    KeywardDbContext db,
    IClock clock,
    ICurrentTenant tenant) : ISoftwareClientTokenService
{
    public async Task<IssuedSoftwareClientToken> IssueAsync(IssueSoftwareClientTokenCommand cmd, CancellationToken ct = default)
    {
        EnsureTenantScope(cmd.TenantId);

        var environmentName = EnvironmentName.Create(cmd.Environment);
        var environment = await db.RuntimeEnvironments
            .FirstOrDefaultAsync(e => e.ProjectId == cmd.ProjectId && e.Name == environmentName, ct)
            .ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Environment '{cmd.Environment}' not found in project {cmd.ProjectId}.");

        var generated = SoftwareClientTokenGenerator.Generate();
        var token = new SoftwareClientToken(
            Guid.NewGuid(), cmd.TenantId, cmd.ProjectId, environment.Id, cmd.Name,
            generated.Prefix, generated.Hash, cmd.ActorUserId, clock.UtcNow, cmd.ExpiresAt, cmd.Note);

        db.SoftwareClientTokens.Add(token);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);

        return new IssuedSoftwareClientToken(token.Id, generated.Token, generated.Prefix, token.ExpiresAt);
    }

    public async Task<IssuedSoftwareClientToken> RotateAsync(Guid tenantId, Guid tokenId, DateTimeOffset? expiresAt, Guid? actorUserId, CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);

        var token = await FindAsync(tenantId, tokenId, ct).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Token {tokenId} not found.");

        // Rotation renews the secret only; keep the token's existing expiry unless the caller supplies a new
        // one (so a rotate can't silently turn a 30-day token into one that never expires). Removing the
        // expiry is therefore a deliberate, separate action, not a side effect of rotating.
        var effectiveExpiry = expiresAt ?? token.ExpiresAt;
        var generated = SoftwareClientTokenGenerator.Generate();
        token.Rotate(generated.Prefix, generated.Hash, clock.UtcNow, effectiveExpiry);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);

        return new IssuedSoftwareClientToken(token.Id, generated.Token, generated.Prefix, token.ExpiresAt);
    }

    public async Task RevokeAsync(Guid tenantId, Guid tokenId, Guid? actorUserId, CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);

        var token = await FindAsync(tenantId, tokenId, ct).ConfigureAwait(false);
        if (token is null)
        {
            return;
        }

        token.Revoke(clock.UtcNow);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<SoftwareClientTokenInfo>> ListAsync(Guid tenantId, Guid projectId, CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);

        var now = clock.UtcNow;
        var tokens = await db.SoftwareClientTokens
            .Where(t => t.TenantId == tenantId && t.ProjectId == projectId)
            .OrderByDescending(t => t.CreatedAt)
            .ToListAsync(ct)
            .ConfigureAwait(false);

        return tokens
            .Select(t => new SoftwareClientTokenInfo(
                t.Id, t.ProjectId, t.EnvironmentId, t.Name, t.Note, t.TokenPrefix,
                t.CreatedAt, t.ExpiresAt, t.LastRotatedAt, t.RevokedAt, t.IsActive(now)))
            .ToList();
    }

    public async Task UpdateAsync(Guid tenantId, Guid tokenId, string name, string note, Guid? actorUserId, CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);

        var token = await FindAsync(tenantId, tokenId, ct).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Token {tokenId} not found.");

        token.UpdateDetails(name, note);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    private Task<SoftwareClientToken?> FindAsync(Guid tenantId, Guid tokenId, CancellationToken ct) =>
        db.SoftwareClientTokens.FirstOrDefaultAsync(t => t.Id == tokenId && t.TenantId == tenantId, ct);

    private void EnsureTenantScope(Guid requestedTenantId)
    {
        if (tenant.TenantId != requestedTenantId)
        {
            throw new UnauthorizedAccessException(
                "Tenant scope mismatch: the request's tenant does not match the authenticated scope.");
        }
    }
}
