using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Agent;
using Am.Keyward.Core.Domain.ValueObjects;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Am.Keyward.Infrastructure.Auth;

/// <summary>
/// <see cref="IAgentApplicationService"/>: decides the token's reach on every call from the current database state
/// (revoking the token, dropping an application from its allowlist or withdrawing the user's software-operator role
/// takes effect on the next call), then delegates every change to <see cref="IProjectService"/> and
/// <see cref="ISoftwareSecretService"/> — the same code path, validation and audit as the UI.
/// </summary>
public sealed class AgentApplicationService(
    IDbContextFactory<KeywardDbContext> dbFactory,
    IClock clock,
    ICurrentTenant tenant,
    ICurrentUser currentUser,
    IProjectService projects,
    ISoftwareSecretService secrets,
    DbAuditSink audit) : IAgentApplicationService
{
    public async Task<IReadOnlyList<AgentApplicationView>> ListAsync(Guid tokenId, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var reach = await ReachAsync(db, tokenId, ct).ConfigureAwait(false);
        var views = await ViewsAsync(db, tokenId, reach.ApplicationIds, ct).ConfigureAwait(false);

        // Metadata only, but still a look into the tenant's applications: one audit entry per listing, as for a vault search.
        await audit.AppendAsync(db, new AuditRequest(reach.TenantId, AuditAction.Read, "ApplicationList", null, reach.UserId), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
        return views;
    }

    public async Task<AgentApplicationView> GetAsync(Guid tokenId, Guid applicationId, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var reach = await ReachAsync(db, tokenId, ct).ConfigureAwait(false);
        EnsureReachable(reach, applicationId);
        return (await ViewsAsync(db, tokenId, [applicationId], ct).ConfigureAwait(false)).Single();
    }

    public async Task<Guid> CreateAsync(Guid tokenId, string name, IReadOnlyList<string> environments, CancellationToken ct = default)
    {
        Reach reach;
        await using (var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false))
        {
            reach = await ReachAsync(db, tokenId, ct).ConfigureAwait(false);
        }

        if (!reach.MayCreate)
        {
            throw new AgentApplicationChangeRefusedException("This agent token may not create applications; a person can allow it on the agent tokens page.");
        }

        // Validated up front, so a bad name does not leave a half-created application behind.
        var requested = environments.Select(e => EnvironmentName.Create(e)).DistinctBy(e => e.Value.ToUpperInvariant()).ToList();
        var applicationId = await Conflicts(() => projects.CreateAsync(reach.TenantId, name, reach.UserId, ct)).ConfigureAwait(false);

        var existing = await secrets.ListEnvironmentsAsync(reach.TenantId, applicationId, ct).ConfigureAwait(false);
        foreach (var environment in requested.Where(e => !existing.Any(x => SameName(x.Name, e.Value))))
        {
            await secrets.AddEnvironmentAsync(reach.TenantId, applicationId, environment.Value, reach.UserId, ct).ConfigureAwait(false);
        }

        return applicationId;
    }

    public async Task AddEnvironmentAsync(Guid tokenId, Guid applicationId, string environment, CancellationToken ct = default)
    {
        var reach = await ReachableAsync(tokenId, applicationId, ct).ConfigureAwait(false);
        var name = EnvironmentName.Create(environment);
        var existing = await secrets.ListEnvironmentsAsync(reach.TenantId, applicationId, ct).ConfigureAwait(false);
        if (existing.Any(e => SameName(e.Name, name.Value)))
        {
            throw new AgentApplicationConflictException($"The environment '{name.Value}' already exists in this application.");
        }

        await secrets.AddEnvironmentAsync(reach.TenantId, applicationId, name.Value, reach.UserId, ct).ConfigureAwait(false);
    }

    public async Task<StoredSecretValue?> CreateSecretAsync(
        Guid tokenId, Guid applicationId, string key, string? environment, string? value, CancellationToken ct = default)
    {
        var reach = await ReachableAsync(tokenId, applicationId, ct).ConfigureAwait(false);
        var secretKey = SecretKey.Create(key);
        if (value is null)
        {
            if (environment is not null)
            {
                await EnsureEnvironmentAsync(reach, applicationId, environment, ct).ConfigureAwait(false);
            }

            return await secrets.CreateSecretAsync(reach.TenantId, applicationId, secretKey.Value, reach.UserId, ct).ConfigureAwait(false)
                ? null
                : throw KeyExists(secretKey);
        }

        if (environment is null)
        {
            throw new ArgumentException("A value needs the environment it belongs to.", nameof(environment));
        }

        await EnsureEnvironmentAsync(reach, applicationId, environment, ct).ConfigureAwait(false);
        if (await KeyExistsAsync(applicationId, secretKey, ct).ConfigureAwait(false))
        {
            throw KeyExists(secretKey);
        }

        // «No value yet» as the precondition: a concurrent create of the same key loses cleanly instead of versioning.
        return await secrets.StoreAsync(new StoreSoftwareSecretCommand(
            reach.TenantId, applicationId, environment, secretKey.Value, value, reach.UserId, new SecretValuePrecondition(null)), ct).ConfigureAwait(false);
    }

    public async Task<StoredSecretValue> SetSecretValueAsync(
        Guid tokenId, Guid applicationId, string key, string environment, string value, SecretValuePrecondition precondition,
        CancellationToken ct = default)
    {
        var reach = await ReachableAsync(tokenId, applicationId, ct).ConfigureAwait(false);
        var secretKey = SecretKey.Create(key);
        if (!await KeyExistsAsync(applicationId, secretKey, ct).ConfigureAwait(false))
        {
            throw new AgentApplicationNotFoundException();
        }

        await EnsureEnvironmentAsync(reach, applicationId, environment, ct).ConfigureAwait(false);
        return await secrets.StoreAsync(new StoreSoftwareSecretCommand(
            reach.TenantId, applicationId, environment, secretKey.Value, value, reach.UserId, precondition), ct).ConfigureAwait(false);
    }

    public async Task RenameSecretAsync(Guid tokenId, Guid applicationId, string key, string newKey, CancellationToken ct = default)
    {
        var reach = await ReachableAsync(tokenId, applicationId, ct).ConfigureAwait(false);
        var secretKey = SecretKey.Create(key);
        var target = SecretKey.Create(newKey);
        await EnsureOwnEmptySecretAsync(tokenId, applicationId, secretKey, ct).ConfigureAwait(false);
        await Conflicts(async () =>
        {
            await secrets.RenameSecretAsync(reach.TenantId, applicationId, secretKey.Value, target.Value, reach.UserId, ct).ConfigureAwait(false);
            return true;
        }).ConfigureAwait(false);
    }

    public async Task DeleteSecretAsync(Guid tokenId, Guid applicationId, string key, CancellationToken ct = default)
    {
        var reach = await ReachableAsync(tokenId, applicationId, ct).ConfigureAwait(false);
        var secretKey = SecretKey.Create(key);
        await EnsureOwnEmptySecretAsync(tokenId, applicationId, secretKey, ct).ConfigureAwait(false);
        await secrets.DeleteSecretAsync(reach.TenantId, applicationId, secretKey.Value, reach.UserId, ct).ConfigureAwait(false);
    }

    public async Task RenameAsync(Guid tokenId, Guid applicationId, string name, CancellationToken ct = default)
    {
        var reach = await ReachableAsync(tokenId, applicationId, ct).ConfigureAwait(false);
        await EnsureOwnEmptyApplicationAsync(tokenId, applicationId, ct).ConfigureAwait(false);
        await Conflicts(async () =>
        {
            await projects.RenameAsync(reach.TenantId, applicationId, name, reach.UserId, ct).ConfigureAwait(false);
            return true;
        }).ConfigureAwait(false);
    }

    public async Task DeleteAsync(Guid tokenId, Guid applicationId, CancellationToken ct = default)
    {
        var reach = await ReachableAsync(tokenId, applicationId, ct).ConfigureAwait(false);
        await EnsureOwnEmptyApplicationAsync(tokenId, applicationId, ct).ConfigureAwait(false);
        await projects.DeleteAsync(reach.TenantId, applicationId, reach.UserId, ct).ConfigureAwait(false);
    }

    private sealed record Reach(Guid TenantId, Guid UserId, bool MayCreate, IReadOnlySet<Guid> ApplicationIds);

    // The one reach decision: an active token with the permission, in its own tenant and acting as its own user,
    // whose user may still manage the software side. Reach = allowlist plus what the token created.
    private async Task<Reach> ReachAsync(KeywardDbContext db, Guid tokenId, CancellationToken ct)
    {
        var token = await db.AgentTokens.AsNoTracking()
            .Include(t => t.AllowedApplications)
            .FirstOrDefaultAsync(t => t.Id == tokenId, ct)
            .ConfigureAwait(false);
        if (token is null
            || !token.IsActive(clock.UtcNow)
            || !token.Allows(AgentScopes.ManageApplications)
            || tenant.TenantId != token.TenantId
            || currentUser.UserId != token.UserId
            || !await SoftwareOperatorGuard.IsOperatorAsync(db, token.TenantId, token.UserId, ct).ConfigureAwait(false))
        {
            throw new AgentApplicationsNotPermittedException();
        }

        var allowlisted = token.AllowedApplications.Select(a => a.ProjectId).ToList();
        var reachable = await db.Projects.AsNoTracking()
            .Where(p => p.TenantId == token.TenantId && (allowlisted.Contains(p.Id) || p.CreatedByAgentTokenId == tokenId))
            .Select(p => p.Id)
            .ToListAsync(ct)
            .ConfigureAwait(false);
        return new Reach(token.TenantId, token.UserId, token.MayCreateApplications, reachable.ToHashSet());
    }

    private async Task<Reach> ReachableAsync(Guid tokenId, Guid applicationId, CancellationToken ct)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var reach = await ReachAsync(db, tokenId, ct).ConfigureAwait(false);
        EnsureReachable(reach, applicationId);
        return reach;
    }

    private static void EnsureReachable(Reach reach, Guid applicationId)
    {
        if (!reach.ApplicationIds.Contains(applicationId))
        {
            throw new AgentApplicationNotFoundException();
        }
    }

    private async Task<IReadOnlyList<AgentApplicationView>> ViewsAsync(
        KeywardDbContext db, Guid tokenId, IReadOnlyCollection<Guid> applicationIds, CancellationToken ct)
    {
        if (applicationIds.Count == 0)
        {
            return [];
        }

        var ids = applicationIds.ToList();
        var apps = await db.Projects.AsNoTracking()
            .Where(p => ids.Contains(p.Id))
            .Select(p => new { p.Id, p.Name, p.CreatedByAgentTokenId })
            .ToListAsync(ct)
            .ConfigureAwait(false);
        var environments = await db.RuntimeEnvironments.AsNoTracking()
            .Where(e => ids.Contains(e.ProjectId))
            .Select(e => new { e.Id, e.ProjectId, e.Name, e.SortOrder })
            .ToListAsync(ct)
            .ConfigureAwait(false);
        var keys = await db.SoftwareSecrets.AsNoTracking()
            .Where(s => ids.Contains(s.ProjectId))
            .Select(s => new { s.Id, s.ProjectId, s.Key, s.CreatedByAgentTokenId })
            .ToListAsync(ct)
            .ConfigureAwait(false);
        var secretIds = keys.Select(k => k.Id).ToList();

        // Only the version pointer — the encrypted versions are never loaded here.
        var values = await db.SecretValues.AsNoTracking()
            .Where(v => secretIds.Contains(v.SoftwareSecretId))
            .Select(v => new { v.SoftwareSecretId, v.EnvironmentId, v.CurrentVersionId })
            .ToListAsync(ct)
            .ConfigureAwait(false);

        return apps
            .OrderBy(a => a.Name, StringComparer.OrdinalIgnoreCase)
            .Select(app =>
            {
                var appEnvironments = environments.Where(e => e.ProjectId == app.Id).OrderBy(e => e.SortOrder).ThenBy(e => e.Name.Value).ToList();
                var appKeys = keys.Where(k => k.ProjectId == app.Id).OrderBy(k => k.Key.Value, StringComparer.OrdinalIgnoreCase)
                    .Select(k => new AgentSecretKeyView(
                        k.Key.Value,
                        k.CreatedByAgentTokenId == tokenId,
                        appEnvironments.Select(e =>
                        {
                            var version = values.FirstOrDefault(v => v.SoftwareSecretId == k.Id && v.EnvironmentId == e.Id)?.CurrentVersionId;
                            return new AgentSecretValueState(e.Name.Value, version is not null, version);
                        }).ToList()))
                    .ToList();
                return new AgentApplicationView(
                    app.Id, app.Name, app.CreatedByAgentTokenId == tokenId, appEnvironments.Select(e => e.Name.Value).ToList(), appKeys);
            })
            .ToList();
    }

    private async Task EnsureEnvironmentAsync(Reach reach, Guid applicationId, string environment, CancellationToken ct)
    {
        var name = EnvironmentName.Create(environment);
        var existing = await secrets.ListEnvironmentsAsync(reach.TenantId, applicationId, ct).ConfigureAwait(false);
        if (!existing.Any(e => SameName(e.Name, name.Value)))
        {
            throw new ArgumentException(
                $"The environment '{name.Value}' does not exist in this application ({string.Join(", ", existing.Select(e => e.Name))}); add it first.");
        }
    }

    private async Task<bool> KeyExistsAsync(Guid applicationId, SecretKey key, CancellationToken ct)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var keys = await db.SoftwareSecrets.AsNoTracking()
            .Where(s => s.ProjectId == applicationId)
            .Select(s => s.Key)
            .ToListAsync(ct)
            .ConfigureAwait(false);
        return keys.Any(k => SameName(k.Value, key.Value));
    }

    // T2 A: only what this token created, and only while nothing a person could rely on hangs on it — no value
    // row (not even a rotation note) in any environment.
    private async Task EnsureOwnEmptySecretAsync(Guid tokenId, Guid applicationId, SecretKey key, CancellationToken ct)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var secret = await db.SoftwareSecrets.AsNoTracking()
            .Where(s => s.ProjectId == applicationId && s.Key == key)
            .Select(s => new { s.Id, s.CreatedByAgentTokenId })
            .FirstOrDefaultAsync(ct)
            .ConfigureAwait(false)
            ?? throw new AgentApplicationNotFoundException();

        if (secret.CreatedByAgentTokenId != tokenId || await db.SecretValues.AnyAsync(v => v.SoftwareSecretId == secret.Id, ct).ConfigureAwait(false))
        {
            throw new AgentApplicationChangeRefusedException(
                "An agent may rename or delete only keys it created itself that hold no value yet; ask a person to do it on the applications page.");
        }
    }

    private async Task EnsureOwnEmptyApplicationAsync(Guid tokenId, Guid applicationId, CancellationToken ct)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var createdBy = await db.Projects.AsNoTracking()
            .Where(p => p.Id == applicationId)
            .Select(p => p.CreatedByAgentTokenId)
            .FirstOrDefaultAsync(ct)
            .ConfigureAwait(false);
        var foreignOrFilled = await db.SoftwareSecrets.AnyAsync(
                s => s.ProjectId == applicationId
                    && (s.CreatedByAgentTokenId != tokenId || s.CreatedByAgentTokenId == null || db.SecretValues.Any(v => v.SoftwareSecretId == s.Id)), ct)
            .ConfigureAwait(false);
        var issuedToken = await db.SoftwareClientTokens.AnyAsync(t => t.ProjectId == applicationId && t.TokenHash != "", ct).ConfigureAwait(false);
        if (createdBy != tokenId || foreignOrFilled || issuedToken)
        {
            throw new AgentApplicationChangeRefusedException(
                "An agent may rename or delete only applications it created itself that hold no value, no key of someone else and no issued app token; ask a person to do it on the applications page.");
        }
    }

    private static AgentApplicationConflictException KeyExists(SecretKey key) =>
        new($"The key '{key.Value}' already exists in this application; set its value instead.");

    // The shared services report «name taken» as InvalidOperationException; to the agent that is a conflict.
    private static async Task<T> Conflicts<T>(Func<Task<T>> action)
    {
        try
        {
            return await action().ConfigureAwait(false);
        }
        catch (InvalidOperationException ex) when (ex is not AgentApplicationConflictException)
        {
            throw new AgentApplicationConflictException(ex.Message);
        }
    }

    private static bool SameName(string a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
}
