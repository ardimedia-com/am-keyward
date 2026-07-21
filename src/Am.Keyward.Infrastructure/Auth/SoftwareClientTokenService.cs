using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Software;
using Am.Keyward.Core.Domain.ValueObjects;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Am.Keyward.Infrastructure.Auth;

/// <summary>
/// Issues, rotates, revokes and lists software-client tokens. Issuance returns the plaintext token once;
/// only its hash is persisted. All operations are gated on the server-authoritative current tenant, and every
/// lifecycle change (issue / rotate / revoke / reactivate / delete / update) is written to the tamper-evident
/// audit chain so the minting and revocation of a credential leaves a trace.
/// </summary>
public sealed class SoftwareClientTokenService(
    KeywardDbContext db,
    IClock clock,
    ICurrentTenant tenant,
    IAuditSink audit,
    ICurrentUser currentUser) : ISoftwareClientTokenService
{
    private const string ResourceType = "SoftwareClientToken";
    public async Task<IssuedSoftwareClientToken> IssueAsync(IssueSoftwareClientTokenCommand cmd, CancellationToken ct = default)
    {
        EnsureTenantScope(cmd.TenantId);
        await EnsureSoftwareOperatorAsync(cmd.TenantId, cmd.ActorUserId, ct).ConfigureAwait(false);

        var environmentName = EnvironmentName.Create(cmd.Environment);
        var environment = await db.RuntimeEnvironments
            .FirstOrDefaultAsync(e => e.ProjectId == cmd.ProjectId && e.Name == environmentName, ct)
            .ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Environment '{cmd.Environment}' not found in project {cmd.ProjectId}.");

        // No name given → assign "<application>-<environment>", numbered when taken (-2, -3, …). A custom
        // name (e.g. a host/purpose suffix) stays possible and must be unique within the application.
        var name = string.IsNullOrWhiteSpace(cmd.Name)
            ? await GenerateNameAsync(cmd.TenantId, cmd.ProjectId, environmentName.Value, ct).ConfigureAwait(false)
            : cmd.Name.Trim();
        await EnsureNameFreeAsync(cmd.TenantId, cmd.ProjectId, name, exceptTokenId: null, ct).ConfigureAwait(false);

        var generated = SoftwareClientTokenGenerator.Generate();
        var token = new SoftwareClientToken(
            Guid.NewGuid(), cmd.TenantId, cmd.ProjectId, environment.Id, name,
            generated.Prefix, generated.Hash, cmd.ActorUserId, clock.UtcNow, cmd.ExpiresAt, cmd.Note);

        db.SoftwareClientTokens.Add(token);
        await AuditAsync(cmd.TenantId, AuditAction.Create, token.Id, cmd.ActorUserId, ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);

        return new IssuedSoftwareClientToken(token.Id, generated.Token, generated.Prefix, token.ExpiresAt);
    }

    public async Task<Guid> CreatePendingAsync(Guid tenantId, Guid projectId, Guid environmentId, Guid? actorUserId, CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);

        var environmentName = await db.RuntimeEnvironments
            .Where(e => e.Id == environmentId && e.ProjectId == projectId)
            .Select(e => e.Name)
            .FirstOrDefaultAsync(ct)
            .ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Environment {environmentId} not found in project {projectId}.");

        var name = await GenerateNameAsync(tenantId, projectId, environmentName.Value, ct).ConfigureAwait(false);
        var token = SoftwareClientToken.CreatePending(
            Guid.NewGuid(), tenantId, projectId, environmentId, name, actorUserId, clock.UtcNow);

        db.SoftwareClientTokens.Add(token);
        await AuditAsync(tenantId, AuditAction.Create, token.Id, actorUserId, ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
        return token.Id;
    }

    public async Task<IssuedSoftwareClientToken> RotateAsync(Guid tenantId, Guid tokenId, DateTimeOffset? expiresAt, Guid? actorUserId, CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);
        await EnsureSoftwareOperatorAsync(tenantId, actorUserId, ct).ConfigureAwait(false);

        var token = await FindAsync(tenantId, tokenId, ct).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Token {tokenId} not found.");

        // Rotation renews the secret AND restarts the validity window: without an explicit new expiry the
        // ORIGINAL LIFETIME is re-applied from now (a 30-day token becomes a fresh 30-day token — it can
        // neither stay expired nor silently turn into one that never expires).
        var effectiveExpiry = expiresAt
            ?? (token.ExpiresAt is { } oldExpiry ? clock.UtcNow + (oldExpiry - token.CreatedAt) : null);
        var generated = SoftwareClientTokenGenerator.Generate();
        token.Rotate(generated.Prefix, generated.Hash, clock.UtcNow, effectiveExpiry);
        await AuditAsync(tenantId, AuditAction.Update, token.Id, actorUserId, ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);

        return new IssuedSoftwareClientToken(token.Id, generated.Token, generated.Prefix, token.ExpiresAt);
    }

    public async Task RevokeAsync(Guid tenantId, Guid tokenId, Guid? actorUserId, CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);
        await EnsureSoftwareOperatorAsync(tenantId, actorUserId, ct).ConfigureAwait(false);

        var token = await FindAsync(tenantId, tokenId, ct).ConfigureAwait(false);
        if (token is null)
        {
            return;
        }

        token.Revoke(clock.UtcNow);
        await AuditAsync(tenantId, AuditAction.Revoke, token.Id, actorUserId, ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public async Task ReactivateAsync(Guid tenantId, Guid tokenId, Guid? actorUserId, CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);
        await EnsureSoftwareOperatorAsync(tenantId, actorUserId, ct).ConfigureAwait(false);

        var token = await FindAsync(tenantId, tokenId, ct).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Token {tokenId} not found.");

        if (token.RevokedAt is null)
        {
            return;
        }

        token.Reactivate();
        await AuditAsync(tenantId, AuditAction.Grant, token.Id, actorUserId, ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public async Task DeleteAsync(Guid tenantId, Guid tokenId, Guid? actorUserId, CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);
        await EnsureSoftwareOperatorAsync(tenantId, actorUserId, ct).ConfigureAwait(false);

        var token = await FindAsync(tenantId, tokenId, ct).ConfigureAwait(false);
        if (token is null)
        {
            return;
        }

        db.SoftwareClientTokens.Remove(token);
        await AuditAsync(tenantId, AuditAction.Delete, token.Id, actorUserId, ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<SoftwareClientTokenInfo>> ListAsync(Guid tenantId, Guid projectId, CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);

        var now = clock.UtcNow;
        var tokens = await db.SoftwareClientTokens
            .Where(t => t.TenantId == tenantId && t.ProjectId == projectId)
            .OrderBy(t => t.Name)
            .ToListAsync(ct)
            .ConfigureAwait(false);

        return tokens
            .Select(t => new SoftwareClientTokenInfo(
                t.Id, t.ProjectId, t.EnvironmentId, t.Name, t.Note, t.TokenPrefix,
                t.CreatedAt, t.ExpiresAt, t.LastRotatedAt, t.RevokedAt, t.IsActive(now), t.HasSecret))
            .ToList();
    }

    public async Task UpdateAsync(Guid tenantId, Guid tokenId, string name, string note, Guid? actorUserId, CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);
        await EnsureSoftwareOperatorAsync(tenantId, actorUserId, ct).ConfigureAwait(false);

        var token = await FindAsync(tenantId, tokenId, ct).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Token {tokenId} not found.");

        await EnsureNameFreeAsync(tenantId, token.ProjectId, name, exceptTokenId: tokenId, ct).ConfigureAwait(false);

        token.UpdateDetails(name, note);
        await AuditAsync(tenantId, AuditAction.Update, token.Id, actorUserId, ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    // Minting / rotating / revoking a client token is a software-management action: system admin, tenant
    // admin, OR software manager. (Previously these were gated only by tenant scope — any signed-in tenant
    // user could mint a credential; this closes that gap.) CreatePending is intentionally NOT gated here — it
    // is an internal building block invoked by ProjectService/SoftwareSecretService, which already gate.
    private async Task EnsureSoftwareOperatorAsync(Guid tenantId, Guid? actorUserId, CancellationToken ct)
    {
        var isOperator = actorUserId is { } actor
            && (await db.Users.AnyAsync(u => u.Id == actor && (u.IsSystemAdmin || u.IsSoftwareManager), ct).ConfigureAwait(false)
                || await db.TenantMemberships.AnyAsync(
                    m => m.TenantId == tenantId && m.UserId == actor && m.Role == TenantRole.TenantAdmin, ct).ConfigureAwait(false));
        if (!isOperator)
        {
            throw new UnauthorizedAccessException("Managing client tokens requires the tenant-admin or software-manager role.");
        }
    }

    private Task<SoftwareClientToken?> FindAsync(Guid tenantId, Guid tokenId, CancellationToken ct) =>
        db.SoftwareClientTokens.FirstOrDefaultAsync(t => t.Id == tokenId && t.TenantId == tenantId, ct);

    /// <summary>The default token name: "&lt;application&gt;-&lt;environment&gt;", numbered when already taken.</summary>
    private async Task<string> GenerateNameAsync(Guid tenantId, Guid projectId, string environmentName, CancellationToken ct)
    {
        var projectName = await db.Projects.Where(p => p.Id == projectId).Select(p => p.Name).FirstOrDefaultAsync(ct).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Project {projectId} not found.");

        var baseName = $"{projectName}-{environmentName}".ToLowerInvariant();
        for (var i = 1; ; i++)
        {
            var candidate = i == 1 ? baseName : $"{baseName}-{i}";
            if (!await db.SoftwareClientTokens.AnyAsync(
                    t => t.TenantId == tenantId && t.ProjectId == projectId && t.Name == candidate, ct).ConfigureAwait(false))
            {
                return candidate;
            }
        }
    }

    /// <summary>
    /// Token names are unique per application so they stay identifiable in lists and audits. Multiple
    /// tokens per (application, environment) remain deliberately allowed — e.g. one per deployed host, or
    /// an overlap token during a zero-downtime swap — they just need distinct names.
    /// </summary>
    private async Task EnsureNameFreeAsync(Guid tenantId, Guid projectId, string name, Guid? exceptTokenId, CancellationToken ct)
    {
        var trimmed = name?.Trim() ?? "";
        if (await db.SoftwareClientTokens.AnyAsync(
                t => t.TenantId == tenantId && t.ProjectId == projectId && t.Id != exceptTokenId && t.Name == trimmed, ct)
            .ConfigureAwait(false))
        {
            throw new InvalidOperationException(
                $"A token named '{trimmed}' already exists in this application. Give the new token a distinguishing name (e.g. a host or purpose suffix).");
        }
    }

    private ValueTask AuditAsync(Guid tenantId, AuditAction action, Guid tokenId, Guid? actorUserId, CancellationToken ct) =>
        audit.AppendAsync(new AuditRequest(tenantId, action, ResourceType, tokenId, actorUserId ?? currentUser.UserId), ct);

    private void EnsureTenantScope(Guid requestedTenantId)
    {
        if (tenant.TenantId != requestedTenantId)
        {
            throw new UnauthorizedAccessException(
                "Tenant scope mismatch: the request's tenant does not match the authenticated scope.");
        }
    }
}
