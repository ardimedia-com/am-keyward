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
/// current version and decrypts. Each operation is audited. Every operation runs on its own short-lived
/// context from the factory (Blazor Server: the scope is the circuit, and concurrent component lifecycles
/// must not share one context); the audit entry is staged on that same context, so audit and business
/// write still commit in one SaveChanges.
/// </summary>
public sealed class SoftwareSecretService(
    IDbContextFactory<KeywardDbContext> dbFactory,
    ISecretBackend backend,
    DbAuditSink audit,
    IClock clock,
    ICurrentTenant tenant,
    ICurrentUser currentUser,
    IKeywardAccessPolicy authorization,
    ISoftwareClientTokenService tokens,
    ISecretReadRecorder readStatistics) : ISoftwareSecretService, ISoftwareSecretReader
{
    private const int AlgVersion = 1;

    public async Task<IReadOnlyList<EnvironmentInfo>> ListEnvironmentsAsync(Guid tenantId, Guid projectId, CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);

        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var environments = await db.RuntimeEnvironments.AsNoTracking()
            .Where(e => e.ProjectId == projectId)
            .OrderBy(e => e.SortOrder).ThenBy(e => e.Name)
            .ToListAsync(ct)
            .ConfigureAwait(false);
        return environments.Select(e => new EnvironmentInfo(e.Id, e.Name.Value)).ToList();
    }

    public async Task RenameEnvironmentAsync(Guid tenantId, Guid projectId, Guid environmentId, string newName, Guid? actorUserId, CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        await EnsureSoftwareOperatorAsync(db, tenantId, actorUserId, ct).ConfigureAwait(false);

        var environment = await db.RuntimeEnvironments
            .FirstOrDefaultAsync(e => e.Id == environmentId && e.ProjectId == projectId, ct).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Environment {environmentId} not found.");

        var name = EnvironmentName.Create(newName);
        if (await db.RuntimeEnvironments.AnyAsync(
                e => e.ProjectId == projectId && e.Id != environmentId && e.Name == name, ct).ConfigureAwait(false))
        {
            throw new InvalidOperationException($"Environment '{name}' already exists in this project.");
        }

        environment.Rename(name);
        await audit.AppendAsync(db, new AuditRequest(tenantId, AuditAction.Update, "Environment", environmentId, actorUserId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public async Task DeleteEnvironmentAsync(Guid tenantId, Guid projectId, Guid environmentId, Guid? actorUserId, CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        await EnsureSoftwareOperatorAsync(db, tenantId, actorUserId, ct).ConfigureAwait(false);

        var environment = await db.RuntimeEnvironments
            .FirstOrDefaultAsync(e => e.Id == environmentId && e.ProjectId == projectId, ct).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Environment {environmentId} not found.");

        // A project must keep at least one environment — secrets and tokens have nowhere to live otherwise.
        if (!await db.RuntimeEnvironments.AnyAsync(e => e.ProjectId == projectId && e.Id != environmentId, ct).ConfigureAwait(false))
        {
            throw new InvalidOperationException("The project's last environment cannot be deleted.");
        }

        // Everything scoped to the environment goes with it: its secret values (versions cascade), its
        // read-statistics rows (no FK to the environment — see SecretReadAccess), and its app tokens (they
        // could never read anything again — the deletion itself stays in the audit chain).
        var values = await db.SecretValues.Where(v => v.EnvironmentId == environmentId).ToListAsync(ct).ConfigureAwait(false);
        db.SecretValues.RemoveRange(values);
        var readAccesses = await db.SecretReadAccesses.Where(r => r.EnvironmentId == environmentId).ToListAsync(ct).ConfigureAwait(false);
        db.SecretReadAccesses.RemoveRange(readAccesses);
        var environmentTokens = await db.SoftwareClientTokens
            .Where(t => t.EnvironmentId == environmentId)
            .ToListAsync(ct).ConfigureAwait(false);
        db.SoftwareClientTokens.RemoveRange(environmentTokens);

        db.RuntimeEnvironments.Remove(environment);

        // Each destroyed credential leaves its own trace in the audit chain, plus the environment entry.
        foreach (var token in environmentTokens)
        {
            await audit.AppendAsync(db, new AuditRequest(tenantId, AuditAction.Delete, "SoftwareClientToken", token.Id, actorUserId), ct).ConfigureAwait(false);
        }

        await audit.AppendAsync(db, new AuditRequest(tenantId, AuditAction.Delete, "Environment", environmentId, actorUserId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    // Managing the software side (environments AND per-environment data/secrets) requires a system admin,
    // a tenant admin, OR a software manager. NOTE: this gates the UI mutation paths only — the token-
    // authenticated client READ paths (ReadAsync/ReadAllAsync) stay tenant-scoped (the token is the auth).
    private static async Task EnsureSoftwareOperatorAsync(KeywardDbContext db, Guid tenantId, Guid? actorUserId, CancellationToken ct)
    {
        // A null actor is a trusted/system caller: the management API authorizes at the HTTP layer (its
        // managementPolicy) before calling in, and seed/system operations attribute no user. Every UI call
        // carries the acting user, and THAT must be an operator (system-admin / software-manager / tenant-admin).
        if (actorUserId is not { } actor)
        {
            return;
        }

        var isOperator = await db.Users.AnyAsync(u => u.Id == actor && (u.IsSystemAdmin || u.IsSoftwareManager), ct).ConfigureAwait(false)
            || await db.TenantMemberships.AnyAsync(
                m => m.TenantId == tenantId && m.UserId == actor && m.Role == TenantRole.TenantAdmin, ct).ConfigureAwait(false);
        if (!isOperator)
        {
            throw new UnauthorizedAccessException("Managing application data requires the tenant-admin or software-manager role.");
        }
    }

    public async Task AddEnvironmentAsync(Guid tenantId, Guid projectId, string name, Guid? actorUserId, CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);

        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        await EnsureSoftwareOperatorAsync(db, tenantId, actorUserId, ct).ConfigureAwait(false);

        var project = await db.Projects.Include(p => p.Environments)
            .FirstOrDefaultAsync(p => p.Id == projectId, ct).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Project {projectId} not found.");

        var environment = project.AddEnvironment(Guid.NewGuid(), EnvironmentName.Create(name), clock.UtcNow);
        db.RuntimeEnvironments.Add(environment); // new child of a tracked aggregate -> mark Added explicitly
        await audit.AppendAsync(db, new AuditRequest(tenantId, AuditAction.Create, "Environment", environment.Id, actorUserId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);

        // A new environment starts with a pending app token (no secret yet), like at application creation.
        await tokens.CreatePendingAsync(tenantId, projectId, environment.Id, actorUserId, ct).ConfigureAwait(false);
    }

    public async Task StoreAsync(StoreSoftwareSecretCommand cmd, CancellationToken ct = default)
    {
        EnsureTenantScope(cmd.TenantId);
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        await EnsureSoftwareOperatorAsync(db, cmd.TenantId, cmd.ActorUserId, ct).ConfigureAwait(false);
        await EnsureAuthorizedAsync(cmd.ProjectId, Permission.Write, ct).ConfigureAwait(false);

        var environment = await ResolveEnvironmentAsync(db, cmd.ProjectId, cmd.Environment, ct)
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
            db, new AuditRequest(cmd.TenantId, AuditAction.Update, "SoftwareSecret", secret.Id, cmd.ActorUserId ?? currentUser.UserId), ct)
            .ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public async Task<string?> ReadAsync(ReadSoftwareSecretQuery query, CancellationToken ct = default)
    {
        EnsureTenantScope(query.TenantId);
        await EnsureAuthorizedAsync(query.ProjectId, Permission.Read, ct).ConfigureAwait(false);

        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var environment = await ResolveEnvironmentAsync(db, query.ProjectId, query.Environment, ct).ConfigureAwait(false);
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

        readStatistics.Record(query.TenantId, secret.Id, environment.Id, SecretReadSource.InProcess);
        await audit.AppendAsync(
            db, new AuditRequest(query.TenantId, AuditAction.Read, "SoftwareSecret", secret.Id, query.ActorUserId ?? currentUser.UserId), ct)
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

        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
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

        readStatistics.Record(tenantId, secret.Id, environmentId, SecretReadSource.Client);
        await audit.AppendAsync(
            db, new AuditRequest(tenantId, AuditAction.Read, "SoftwareSecret", secret.Id, actorUserId), ct)
            .ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);

        return plaintext;
    }

    public async Task<IReadOnlyList<KeyValuePair<string, string>>> ReadAllAsync(
        Guid tenantId, Guid projectId, Guid environmentId, Guid? actorUserId, CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);
        await EnsureAuthorizedAsync(projectId, Permission.Read, ct).ConfigureAwait(false);

        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
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
            readStatistics.Record(tenantId, secret.Id, environmentId, SecretReadSource.Client);
        }

        await audit.AppendAsync(
            db, new AuditRequest(tenantId, AuditAction.Read, "SoftwareSecret", null, actorUserId), ct)
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

    // --- management surface (list / view / delete by key) ---

    public async Task<IReadOnlyList<SoftwareSecretSummary>> ListSecretsAsync(Guid tenantId, Guid projectId, CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);
        await EnsureAuthorizedAsync(projectId, Permission.Read, ct).ConfigureAwait(false);

        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var envs = await db.RuntimeEnvironments
            .Where(e => e.ProjectId == projectId)
            .ToListAsync(ct)
            .ConfigureAwait(false);
        var envNames = envs.ToDictionary(e => e.Id, e => e.Name.Value);
        // (SortOrder, canonical rank) so an all-zero SortOrder still yields Development/Test/Production
        // rather than the alphabet — see EnvironmentOrder.
        var envOrder = envs.ToDictionary(e => e.Id, e => (e.SortOrder, EnvironmentOrder.CanonicalRank(e.Name.Value)));

        var secrets = await db.SoftwareSecrets
            .Where(s => s.ProjectId == projectId)
            .Include(s => s.Values)
            .ToListAsync(ct)
            .ConfigureAwait(false);

        return secrets
            .Select(s => new SoftwareSecretSummary(
                s.Key.Value,
                s.Values.Where(v => v.CurrentVersionId != null)
                    .OrderBy(v => envOrder.GetValueOrDefault(v.EnvironmentId, (int.MaxValue, int.MaxValue)))
                    .ThenBy(v => envNames.GetValueOrDefault(v.EnvironmentId, "?"))
                    .Select(v => envNames.GetValueOrDefault(v.EnvironmentId, "?"))
                    .ToList()))
            .OrderBy(s => s.Key, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public async Task<SoftwareSecretDetail?> GetSecretAsync(Guid tenantId, Guid projectId, string key, CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);
        await EnsureAuthorizedAsync(projectId, Permission.Read, ct).ConfigureAwait(false);

        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var secretKey = SecretKey.Create(key);
        var environments = await db.RuntimeEnvironments
            .Where(e => e.ProjectId == projectId)
            .ToListAsync(ct)
            .ConfigureAwait(false);

        var secret = await db.SoftwareSecrets
            .Include(s => s.Values).ThenInclude(v => v.Versions)
            .FirstOrDefaultAsync(s => s.ProjectId == projectId && s.Key == secretKey, ct)
            .ConfigureAwait(false);
        if (secret is null)
        {
            return null;
        }

        // Read statistics (last read at/via, total count) — shown per environment so the management view
        // answers "is this secret still used?". A view like this one deliberately does not count as a read.
        var readAccesses = await db.SecretReadAccesses.AsNoTracking()
            .Where(r => r.SoftwareSecretId == secret.Id)
            .ToListAsync(ct)
            .ConfigureAwait(false);

        var values = new List<SecretEnvironmentValue>();
        foreach (var environment in environments
            .OrderBy(e => e.SortOrder)
            .ThenBy(e => EnvironmentOrder.CanonicalRank(e.Name.Value))
            .ThenBy(e => e.Name.Value, StringComparer.OrdinalIgnoreCase))
        {
            var read = readAccesses.FirstOrDefault(r => r.EnvironmentId == environment.Id);
            var value = secret.Values.FirstOrDefault(v => v.EnvironmentId == environment.Id);
            // A value row can exist WITHOUT a version — it then carries only the rotation metadata (see
            // SoftwareSecret.EnsureValue), so the date/note are read from it either way.
            if (value?.CurrentVersionId is null)
            {
                values.Add(new SecretEnvironmentValue(
                    environment.Name.Value, false, null, read?.LastReadAt, read?.LastReadSource.ToString(), read?.ReadCount ?? 0,
                    value?.ExpiresAt, value?.Note ?? ""));
                continue;
            }

            var plaintext = await DecryptCurrentAsync(tenantId, projectId, environment.Id, secret.Id, value, ct).ConfigureAwait(false);
            values.Add(new SecretEnvironmentValue(
                environment.Name.Value, true, plaintext, read?.LastReadAt, read?.LastReadSource.ToString(), read?.ReadCount ?? 0,
                value.ExpiresAt, value.Note));
        }

        await audit.AppendAsync(db, new AuditRequest(tenantId, AuditAction.Read, "SoftwareSecret", secret.Id, currentUser.UserId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);

        return new SoftwareSecretDetail(secret.Key.Value, values);
    }

    public async Task RenameSecretAsync(
        Guid tenantId, Guid projectId, string key, string newKey, Guid? actorUserId, CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        await EnsureSoftwareOperatorAsync(db, tenantId, actorUserId, ct).ConfigureAwait(false);
        await EnsureAuthorizedAsync(projectId, Permission.Write, ct).ConfigureAwait(false);

        var currentKey = SecretKey.Create(key);
        var targetKey = SecretKey.Create(newKey);

        var secret = await db.SoftwareSecrets
            .FirstOrDefaultAsync(s => s.ProjectId == projectId && s.Key == currentKey, ct)
            .ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Secret '{currentKey}' not found in project {projectId}.");

        if (currentKey == targetKey)
        {
            return;
        }

        // One key per project — the unique index would reject it anyway; fail with a usable message first.
        // Compared case-insensitively to match how the UI de-duplicates keys.
        var conflicting = await db.SoftwareSecrets
            .Where(s => s.ProjectId == projectId && s.Id != secret.Id)
            .Select(s => s.Key)
            .ToListAsync(ct)
            .ConfigureAwait(false);
        if (conflicting.Any(k => string.Equals(k.Value, targetKey.Value, StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException($"The key '{targetKey}' already exists in this project.");
        }

        // Values and versions stay as they are: the envelope AAD binds tenant/project/environment/secret/
        // version IDs, never the key — so nothing has to be re-encrypted.
        secret.Rename(targetKey);
        await audit.AppendAsync(
            db, new AuditRequest(tenantId, AuditAction.Update, "SoftwareSecret", secret.Id, actorUserId ?? currentUser.UserId), ct)
            .ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public async Task DeleteSecretAsync(Guid tenantId, Guid projectId, string key, Guid? actorUserId, CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        await EnsureSoftwareOperatorAsync(db, tenantId, actorUserId, ct).ConfigureAwait(false);
        await EnsureAuthorizedAsync(projectId, Permission.Write, ct).ConfigureAwait(false);

        var secretKey = SecretKey.Create(key);
        var secret = await db.SoftwareSecrets
            .FirstOrDefaultAsync(s => s.ProjectId == projectId && s.Key == secretKey, ct)
            .ConfigureAwait(false);
        if (secret is null)
        {
            return;
        }

        db.SoftwareSecrets.Remove(secret); // values + versions cascade
        await audit.AppendAsync(db, new AuditRequest(tenantId, AuditAction.Delete, "SoftwareSecret", secret.Id, actorUserId ?? currentUser.UserId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public async Task<bool> CreateSecretAsync(Guid tenantId, Guid projectId, string key, Guid? actorUserId, CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        await EnsureSoftwareOperatorAsync(db, tenantId, actorUserId, ct).ConfigureAwait(false);
        await EnsureAuthorizedAsync(projectId, Permission.Write, ct).ConfigureAwait(false);

        var secretKey = SecretKey.Create(key);

        // Compared case-insensitively to match how the UI de-duplicates keys (and the rename guard above).
        var existingKeys = await db.SoftwareSecrets
            .Where(s => s.ProjectId == projectId)
            .Select(s => s.Key)
            .ToListAsync(ct)
            .ConfigureAwait(false);
        if (existingKeys.Any(k => string.Equals(k.Value, secretKey.Value, StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }

        // The key exists without a SecretValue in any environment: it lists with zero environments, the
        // client read paths simply don't deliver it, and values are set later per environment as usual.
        var secret = new SoftwareSecret(Guid.NewGuid(), projectId, tenantId, secretKey, actorUserId, clock.UtcNow);
        db.SoftwareSecrets.Add(secret);
        await audit.AppendAsync(db, new AuditRequest(tenantId, AuditAction.Create, "SoftwareSecret", secret.Id, actorUserId ?? currentUser.UserId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
        return true;
    }

    public async Task SetValueRotationAsync(
        Guid tenantId,
        Guid projectId,
        string key,
        string environment,
        DateTimeOffset? expiresAt,
        string? note,
        Guid? actorUserId,
        CancellationToken ct = default)
    {
        EnsureTenantScope(tenantId);
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        await EnsureSoftwareOperatorAsync(db, tenantId, actorUserId, ct).ConfigureAwait(false);
        await EnsureAuthorizedAsync(projectId, Permission.Write, ct).ConfigureAwait(false);

        var secretKey = SecretKey.Create(key);
        var runtimeEnvironment = await ResolveEnvironmentAsync(db, projectId, environment, ct).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Environment '{environment}' does not exist in this application.");

        var secret = await db.SoftwareSecrets
            .Include(s => s.Values)
            .FirstOrDefaultAsync(s => s.ProjectId == projectId && s.Key == secretKey, ct)
            .ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Secret '{key}' does not exist in this application.");

        // Deliberately creates the value row when the environment has none yet: the rotation note is most
        // valuable BEFORE a value exists ("this is where you get it"). The row stays value-less, which every
        // reader already treats as "no value".
        var existingValue = secret.Values.FirstOrDefault(v => v.EnvironmentId == runtimeEnvironment.Id);
        var value = secret.EnsureValue(Guid.NewGuid(), runtimeEnvironment.Id);
        value.SetRotationMetadata(expiresAt, note);

        // Keys are app-assigned Guids, so EF's graph heuristic (IsKeySet) would mark this new child of a
        // tracked aggregate as Modified -> a 0-row UPDATE. Mark it Added explicitly (same as StoreAsync).
        if (existingValue is null)
        {
            db.SecretValues.Add(value);
        }

        await audit.AppendAsync(
            db,
            new AuditRequest(tenantId, AuditAction.Update, "SecretValueRotation", value.Id, actorUserId ?? currentUser.UserId),
            ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
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
    /// Routes the resource access decision through the central <see cref="IKeywardAccessPolicy"/>, which
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

    private static async Task<RuntimeEnvironment?> ResolveEnvironmentAsync(
        KeywardDbContext db, Guid projectId, string environment, CancellationToken ct)
    {
        var name = EnvironmentName.Create(environment);
        return await db.RuntimeEnvironments
            .FirstOrDefaultAsync(e => e.ProjectId == projectId && e.Name == name, ct)
            .ConfigureAwait(false);
    }
}
