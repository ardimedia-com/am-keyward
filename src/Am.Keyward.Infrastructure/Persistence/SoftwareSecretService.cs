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
    IClock clock) : ISoftwareSecretService
{
    private const int AlgVersion = 1;

    public async Task StoreAsync(StoreSoftwareSecretCommand cmd, CancellationToken ct = default)
    {
        var environment = await ResolveEnvironmentAsync(cmd.ProjectId, cmd.Environment, ct)
            ?? throw new InvalidOperationException($"Environment '{cmd.Environment}' not found in project {cmd.ProjectId}.");

        var key = SecretKey.Create(cmd.Key);
        var secret = await db.SoftwareSecrets
            .Include(s => s.Values).ThenInclude(v => v.Versions)
            .FirstOrDefaultAsync(s => s.ProjectId == cmd.ProjectId && s.Key == key, ct)
            .ConfigureAwait(false);

        var isNew = secret is null;
        secret ??= new SoftwareSecret(Guid.NewGuid(), cmd.ProjectId, key, cmd.ActorUserId, clock.UtcNow);

        var existingValue = secret.Values.FirstOrDefault(v => v.EnvironmentId == environment.Id);
        var valueId = existingValue?.Id ?? Guid.NewGuid();
        var versionId = Guid.NewGuid();

        var aad = Aad.ForSoftwareSecretVersion(cmd.TenantId, cmd.ProjectId, environment.Id, secret.Id, versionId, AlgVersion);
        var encrypted = await backend.ProtectAsync(Encoding.UTF8.GetBytes(cmd.Value), aad, ct).ConfigureAwait(false);
        secret.SetValue(valueId, environment.Id, versionId, encrypted, clock.UtcNow);

        if (isNew)
        {
            db.SoftwareSecrets.Add(secret);
        }

        await audit.AppendAsync(
            new AuditRequest(cmd.TenantId, AuditAction.Update, "SoftwareSecret", secret.Id, cmd.ActorUserId), ct)
            .ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public async Task<string?> ReadAsync(ReadSoftwareSecretQuery query, CancellationToken ct = default)
    {
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

        var version = value.Versions.Single(v => v.Id == value.CurrentVersionId);
        var aad = Aad.ForSoftwareSecretVersion(query.TenantId, query.ProjectId, environment.Id, secret.Id, version.Id, AlgVersion);
        var plaintext = await backend.UnprotectAsync(version.Encrypted, aad, ct).ConfigureAwait(false);

        await audit.AppendAsync(
            new AuditRequest(query.TenantId, AuditAction.Read, "SoftwareSecret", secret.Id, query.ActorUserId), ct)
            .ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);

        return Encoding.UTF8.GetString(plaintext);
    }

    private async Task<RuntimeEnvironment?> ResolveEnvironmentAsync(Guid projectId, string environment, CancellationToken ct)
    {
        var name = EnvironmentName.Create(environment);
        return await db.RuntimeEnvironments
            .FirstOrDefaultAsync(e => e.ProjectId == projectId && e.Name == name, ct)
            .ConfigureAwait(false);
    }
}
