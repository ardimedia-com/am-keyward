using System.Text;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Audit;
using Am.Keyward.Core.Domain.Software;
using Am.Keyward.Core.Domain.ValueObjects;
using Microsoft.EntityFrameworkCore;

namespace Am.Keyward.Infrastructure.Persistence;

/// <summary>
/// Walking-skeleton implementation of the software-credentials use case: encrypts a value into the
/// envelope (binding the full logical slot via AAD) and persists it as a new secret version; reads the
/// current version and decrypts. Each operation is audited.
/// </summary>
public sealed class SoftwareSecretService(
    KeywardDbContext db,
    ISecretBackend backend,
    IAuditSink audit,
    IClock clock,
    ICurrentTenant tenant,
    ICurrentUser currentUser,
    IAuthorizationService authorization) : ISoftwareSecretService, ISoftwareSecretReader
{
    private const int AlgVersion = 1;

    public async Task StoreAsync(StoreSoftwareSecretCommand cmd, CancellationToken ct = default)
    {
        EnsureTenantScope(cmd.TenantId);
        await EnsureAuthorizedAsync(cmd.ProjectId, Permission.Write, ct).ConfigureAwait(false);

        var environment = await ResolveEnvironmentAsync(cmd.ProjectId, cmd.Environment, ct)
            ?? throw new InvalidOperationException($"Environment '{cmd.Environment}' not found in project {cmd.ProjectId}.");

        var key = SecretKey.Create(cmd.Key);
        var secret = await db.SoftwareSecrets
            .Include(s => s.Values).ThenInclude(v => v.Versions)
            .FirstOrDefaultAsync(s => s.ProjectId == cmd.ProjectId && s.Key == key, ct)
            .ConfigureAwait(false);

        var isNew = secret is null;
        secret ??= new SoftwareSecret(Guid.NewGuid(), cmd.ProjectId, cmd.TenantId, key, cmd.ActorUserId, clock.UtcNow);

        var existingValue = secret.Values.FirstOrDefault(v => v.EnvironmentId == environment.Id);
        var valueId = existingValue?.Id ?? Guid.NewGuid();
        var versionId = Guid.NewGuid();

        var aad = Aad.ForSoftwareSecretVersion(cmd.TenantId, cmd.ProjectId, environment.Id, secret.Id, versionId, AlgVersion);
        var encrypted = await backend.ProtectAsync(Encoding.UTF8.GetBytes(cmd.Value), aad, ct).ConfigureAwait(false);
        var secretValue = secret.SetValue(valueId, environment.Id, versionId, encrypted, clock.UtcNow);

        // Keys are app-assigned Guids, so EF's graph state heuristic (IsKeySet) would mis-mark new
        // children as Modified -> a 0-row UPDATE. Mark the genuinely-new entities Added explicitly.
        if (isNew)
        {
            db.SoftwareSecrets.Add(secret);
        }
        else if (existingValue is null)
        {
            db.SecretValues.Add(secretValue);          // new per-environment value (+ its first version)
        }
        else
        {
            db.SecretVersions.Add(secretValue.Current); // new version on an existing per-environment value
        }

        await audit.AppendAsync(
            new AuditRequest(cmd.TenantId, AuditAction.Update, "SoftwareSecret", secret.Id, cmd.ActorUserId), ct)
            .ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public async Task<string?> ReadAsync(ReadSoftwareSecretQuery query, CancellationToken ct = default)
    {
        EnsureTenantScope(query.TenantId);
        await EnsureAuthorizedAsync(query.ProjectId, Permission.Read, ct).ConfigureAwait(false);

        var environment = await ResolveEnvironmentAsync(query.ProjectId, query.Environment, ct).ConfigureAwait(false);
        if (environment is null)
        {
            return null;
        }

        var key = SecretKey.Create(query.Key);
        var secret = await db.SoftwareSecrets
            .Include(s => s.Values).ThenInclude(v => v.Versions)
            .FirstOrDefaultAsync(s => s.ProjectId == query.ProjectId && s.Key == key, ct)
            .ConfigureAwait(false);

        var value = secret?.Values.FirstOrDefault(v => v.EnvironmentId == environment.Id);
        if (secret is null || value?.CurrentVersionId is null)
        {
            return null;
        }

        var plaintext = await DecryptCurrentAsync(query.TenantId, query.ProjectId, environment.Id, secret.Id, value, ct)
            .ConfigureAwait(false);

        await audit.AppendAsync(
            new AuditRequest(query.TenantId, AuditAction.Read, "SoftwareSecret", secret.Id, query.ActorUserId), ct)
            .ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);

        return plaintext;
    }

    // --- ISoftwareSecretReader: the software-client read path (environment fixed by the token) ---

    public async Task<string?> ReadAsync(
        Guid tenantId, Guid projectId, Guid environmentId, string key, Guid? actorUserId, CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);
        await EnsureAuthorizedAsync(projectId, Permission.Read, ct).ConfigureAwait(false);

        var secretKey = SecretKey.Create(key);
        var secret = await db.SoftwareSecrets
            .Include(s => s.Values).ThenInclude(v => v.Versions)
            .FirstOrDefaultAsync(s => s.ProjectId == projectId && s.Key == secretKey, ct)
            .ConfigureAwait(false);

        var value = secret?.Values.FirstOrDefault(v => v.EnvironmentId == environmentId);
        if (secret is null || value?.CurrentVersionId is null)
        {
            return null;
        }

        var plaintext = await DecryptCurrentAsync(tenantId, projectId, environmentId, secret.Id, value, ct)
            .ConfigureAwait(false);

        await audit.AppendAsync(
            new AuditRequest(tenantId, AuditAction.Read, "SoftwareSecret", secret.Id, actorUserId), ct)
            .ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);

        return plaintext;
    }

    public async Task<IReadOnlyList<KeyValuePair<string, string>>> ReadAllAsync(
        Guid tenantId, Guid projectId, Guid environmentId, Guid? actorUserId, CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);
        await EnsureAuthorizedAsync(projectId, Permission.Read, ct).ConfigureAwait(false);

        var secrets = await db.SoftwareSecrets
            .Where(s => s.ProjectId == projectId)
            .Include(s => s.Values).ThenInclude(v => v.Versions)
            .ToListAsync(ct)
            .ConfigureAwait(false);

        var result = new List<KeyValuePair<string, string>>();
        foreach (var secret in secrets)
        {
            var value = secret.Values.FirstOrDefault(v => v.EnvironmentId == environmentId);
            if (value?.CurrentVersionId is null)
            {
                continue;
            }

            var plaintext = await DecryptCurrentAsync(tenantId, projectId, environmentId, secret.Id, value, ct)
                .ConfigureAwait(false);
            result.Add(new KeyValuePair<string, string>(secret.Key.Value, plaintext));
        }

        await audit.AppendAsync(
            new AuditRequest(tenantId, AuditAction.Read, "SoftwareSecret", null, actorUserId), ct)
            .ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);

        return result;
    }

    private async Task<string> DecryptCurrentAsync(
        Guid tenantId, Guid projectId, Guid environmentId, Guid secretId, SecretValue value, CancellationToken ct)
    {
        var version = value.Versions.Single(v => v.Id == value.CurrentVersionId);
        var aad = Aad.ForSoftwareSecretVersion(tenantId, projectId, environmentId, secretId, version.Id, AlgVersion);
        var plaintext = await backend.UnprotectAsync(version.Encrypted, aad, ct).ConfigureAwait(false);
        return Encoding.UTF8.GetString(plaintext);
    }

    /// <summary>
    /// Server-authoritative tenant gate: the command's tenant must match the ambient scope set by the
    /// host edge (route/circuit). This is the central application-level cross-tenant check, backed in
    /// depth by the EF tenant query filter and SQL Server row-level security.
    /// </summary>
    private void EnsureTenantScope(Guid requestedTenantId)
    {
        if (tenant.TenantId != requestedTenantId)
        {
            throw new UnauthorizedAccessException(
                "Tenant scope mismatch: the request's tenant does not match the authenticated scope.");
        }
    }

    /// <summary>
    /// Routes the resource access decision through the central <see cref="IAuthorizationService"/>, which
    /// confirms the project's true owning tenant matches the current scope (catching a "right scope,
    /// foreign project" attempt even if the query filter were bypassed).
    /// </summary>
    private async Task EnsureAuthorizedAsync(Guid projectId, Permission action, CancellationToken ct)
    {
        var allowed = await authorization
            .IsAllowedAsync(currentUser.UserId, new GrantScope(GrantScopeKind.Project, projectId), action, ct)
            .ConfigureAwait(false);
        if (!allowed)
        {
            throw new UnauthorizedAccessException($"Not authorized to {action} project {projectId}.");
        }
    }

    private async Task<RuntimeEnvironment?> ResolveEnvironmentAsync(Guid projectId, string environment, CancellationToken ct)
    {
        var name = EnvironmentName.Create(environment);
        return await db.RuntimeEnvironments
            .FirstOrDefaultAsync(e => e.ProjectId == projectId && e.Name == name, ct)
            .ConfigureAwait(false);
    }
}
