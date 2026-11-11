using System.Security.Cryptography;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.ValueObjects;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Am.Keyward.Infrastructure.Crypto;

/// <summary>The outcome of one <see cref="KekRewrapService.RewrapAsync"/> run.</summary>
/// <param name="TargetKekId">The current KEK every data key was re-wrapped to.</param>
/// <param name="Rewrapped">Data keys re-wrapped by this run.</param>
/// <param name="Unresolvable">Values whose data key the key ring could not open (left untouched).</param>
public sealed record KekRewrapReport(string TargetKekId, int Rewrapped, IReadOnlyList<KekIntegrityIssue> Unresolvable)
{
    /// <summary>True when nothing was left behind under an old KEK id.</summary>
    public bool IsComplete => Unresolvable.Count == 0;
}

/// <summary>
/// The KEK re-wrap job: after a key rotation (a <see cref="KeyRingKekProvider"/> whose CURRENT key is new and whose
/// older keys are still in the ring), it re-wraps every stored data key (DEK) that is still sealed under an older
/// KEK id to the current one, so the old key can be retired from the ring afterwards.
///
/// <para><b>Only data keys move.</b> Each envelope's DEK is unwrapped with its old KEK and wrapped again with the
/// current one; ciphertext, nonce, tag and AAD stay byte-for-byte as they are, so no secret value is ever decrypted
/// and the DEK is zeroed as soon as it is re-wrapped.</para>
///
/// <para><b>Idempotent and resumable.</b> A row already under the current KEK id is skipped, so a run that was
/// interrupted is simply started again; two concurrent runs both produce a valid wrap under the current key.
/// Work happens in batches, each committed together with an audit entry (action <c>Update</c>, resource type
/// <c>KekRewrap</c>) in the chain of the tenant the rows belong to.</para>
///
/// <para>Covers software-secret versions, vault-item versions, the audit subjects' encrypted PII and the key-ownership
/// canary (which must follow the key, or retiring the old key would turn the canary into a conflict). Writes respect
/// row-level security: each batch runs in the scope of the tenant (or, for a personal vault, the owning user) whose
/// rows it changes; only the discovery read uses the system read bypass.</para>
///
/// <para>Refuses to run when the key-ownership check found that this key does not own the database.</para>
/// </summary>
public sealed class KekRewrapService(
    IServiceScopeFactory scopeFactory,
    IKekProvider kek,
    KeywardKeyIntegrityState keyIntegrity,
    ILogger<KekRewrapService>? logger = null)
{
    /// <summary>Rows per committed batch.</summary>
    public const int DefaultBatchSize = 200;

    /// <summary>The audit resource type of a re-wrap batch.</summary>
    public const string AuditResourceType = "KekRewrap";

    private const string SecretVersionKind = "SecretVersion";
    private const string VaultItemVersionKind = "VaultItemVersion";
    private const string AuditSubjectKind = "AuditSubject";

    /// <summary>Re-wraps every data key that is not yet under <see cref="IKekProvider.KekId"/>.</summary>
    public async Task<KekRewrapReport> RewrapAsync(int batchSize = DefaultBatchSize, CancellationToken ct = default)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(batchSize, 1);
        keyIntegrity.ThrowIfBlocked();

        string target = kek.KekId;
        List<KekIntegrityIssue> unresolvable = [];
        List<Pending> pending = await this.DiscoverAsync(target, unresolvable, ct).ConfigureAwait(false);

        int rewrapped = 0;
        foreach (IGrouping<(string Kind, Guid? TenantId, Guid? OwnerUserId), Pending> group in pending
                     .GroupBy(p => (p.Kind, p.TenantId, p.OwnerUserId)))
        {
            foreach (Pending[] batch in group.Chunk(batchSize))
            {
                rewrapped += await this.RewrapBatchAsync(group.Key, [.. batch.Select(p => p.Id)], target, unresolvable, ct)
                    .ConfigureAwait(false);
            }
        }

        if (await this.RewrapCanaryAsync(target, ct).ConfigureAwait(false))
        {
            rewrapped++;
        }

        logger?.LogInformation(
            "KEYWARD: KEK re-wrap to {KekId} finished: {Rewrapped} data key(s) re-wrapped, {Unresolvable} left behind.",
            target, rewrapped, unresolvable.Count);
        if (unresolvable.Count > 0)
        {
            logger?.LogWarning(
                "KEYWARD: {Count} value(s) could not be re-wrapped because the key ring cannot open them (KEK ids: {KekIds}). "
                + "Do NOT retire a key from the ring while values still depend on it.",
                unresolvable.Count, string.Join(", ", unresolvable.Select(u => u.KekId).Distinct(StringComparer.Ordinal)));
        }

        return new KekRewrapReport(target, rewrapped, unresolvable);
    }

    /// <summary>Lists the rows not yet under <paramref name="target"/>; reads only ids and envelopes' KEK ids.</summary>
    private async Task<List<Pending>> DiscoverAsync(string target, List<KekIntegrityIssue> unresolvable, CancellationToken ct)
    {
        using IServiceScope scope = scopeFactory.CreateScope();
        scope.ServiceProvider.GetRequiredService<Tenancy.SystemReadScope>().Enabled = true;
        await using KeywardDbContext db = await scope.ServiceProvider
            .GetRequiredService<IDbContextFactory<KeywardDbContext>>().CreateDbContextAsync(ct).ConfigureAwait(false);

        List<Pending> pending = [];

        var secrets = db.SecretVersions.IgnoreQueryFilters().AsNoTracking()
            .Select(v => new { v.Id, v.TenantId, v.Encrypted })
            .AsAsyncEnumerable();
        await foreach (var row in secrets.WithCancellation(ct).ConfigureAwait(false))
        {
            Classify(SecretVersionKind, row.Id, row.TenantId, null, row.Encrypted.KekId);
        }

        var items = db.VaultItemVersions.IgnoreQueryFilters().AsNoTracking()
            .Select(v => new { v.Id, v.TenantId, v.OwnerUserId, v.Encrypted })
            .AsAsyncEnumerable();
        await foreach (var row in items.WithCancellation(ct).ConfigureAwait(false))
        {
            // A tenant row is written in its tenant's scope; only a personal row needs its owner.
            Classify(VaultItemVersionKind, row.Id, row.TenantId, row.TenantId is null ? row.OwnerUserId : null, row.Encrypted.KekId);
        }

        var subjects = db.AuditSubjects.AsNoTracking()
            .Where(s => s.EncryptedPii != null)
            .Select(s => new { s.Id, s.EncryptedPii })
            .AsAsyncEnumerable();
        await foreach (var row in subjects.WithCancellation(ct).ConfigureAwait(false))
        {
            Classify(AuditSubjectKind, row.Id, null, null, row.EncryptedPii!.KekId);
        }

        return pending;

        void Classify(string kind, Guid id, Guid? tenantId, Guid? ownerUserId, string kekId)
        {
            if (string.Equals(kekId, target, StringComparison.Ordinal))
            {
                return;
            }

            if (kek.CanResolve(kekId))
            {
                pending.Add(new Pending(kind, id, tenantId, ownerUserId));
            }
            else
            {
                unresolvable.Add(new KekIntegrityIssue(kind, id, kekId));
            }
        }
    }

    private async Task<int> RewrapBatchAsync(
        (string Kind, Guid? TenantId, Guid? OwnerUserId) group, Guid[] ids, string target,
        List<KekIntegrityIssue> unresolvable, CancellationToken ct)
    {
        using IServiceScope scope = scopeFactory.CreateScope();
        IServiceProvider sp = scope.ServiceProvider;
        sp.GetRequiredService<ITenantScopeSetter>().SetTenant(group.TenantId);
        sp.GetRequiredService<IUserScopeSetter>().SetUser(group.OwnerUserId);
        sp.GetRequiredService<IActorScopeSetter>().SetSystemActor();

        await using KeywardDbContext db = await sp.GetRequiredService<IDbContextFactory<KeywardDbContext>>()
            .CreateDbContextAsync(ct).ConfigureAwait(false);

        int changed = 0;
        SortedSet<string> fromIds = new(StringComparer.Ordinal);

        async Task<bool> MoveAsync(object entity, string propertyName, EncryptedValue current, Guid id)
        {
            if (string.Equals(current.KekId, target, StringComparison.Ordinal))
            {
                return false;   // already done (a concurrent or earlier run)
            }

            try
            {
                EncryptedValue moved = await this.RewrapAsync(current, ct).ConfigureAwait(false);
                var property = db.Entry(entity).Property(propertyName);
                property.CurrentValue = moved;
                property.IsModified = true;
                fromIds.Add(current.KekId);
                return true;
            }
            catch (Exception ex) when (ex is CryptographicException or InvalidOperationException)
            {
                unresolvable.Add(new KekIntegrityIssue(group.Kind, id, current.KekId));
                return false;
            }
        }

        switch (group.Kind)
        {
            case SecretVersionKind:
                foreach (var row in await db.SecretVersions.IgnoreQueryFilters()
                             .Where(v => ids.Contains(v.Id)).ToListAsync(ct).ConfigureAwait(false))
                {
                    changed += await MoveAsync(row, nameof(row.Encrypted), row.Encrypted, row.Id).ConfigureAwait(false) ? 1 : 0;
                }

                break;

            case VaultItemVersionKind:
                foreach (var row in await db.VaultItemVersions.IgnoreQueryFilters()
                             .Where(v => ids.Contains(v.Id)).ToListAsync(ct).ConfigureAwait(false))
                {
                    changed += await MoveAsync(row, nameof(row.Encrypted), row.Encrypted, row.Id).ConfigureAwait(false) ? 1 : 0;
                }

                break;

            case AuditSubjectKind:
                foreach (var row in await db.AuditSubjects
                             .Where(s => ids.Contains(s.Id)).ToListAsync(ct).ConfigureAwait(false))
                {
                    if (row.EncryptedPii is { } pii)
                    {
                        changed += await MoveAsync(row, nameof(row.EncryptedPii), pii, row.Id).ConfigureAwait(false) ? 1 : 0;
                    }
                }

                break;
        }

        if (changed == 0)
        {
            return 0;
        }

        // The batch and its audit record commit together.
        await sp.GetRequiredService<DbAuditSink>().AppendAsync(db, new AuditRequest(
            group.TenantId, AuditAction.Update, AuditResourceType, ResourceId: null, ActorUserId: null,
            Reason: $"Re-wrapped {changed} {group.Kind} data key(s) from {string.Join(", ", fromIds)} to {target}."),
            ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
        return changed;
    }

    /// <summary>Moves the key-ownership canary to the current KEK, so retiring the old key does not orphan it.</summary>
    private async Task<bool> RewrapCanaryAsync(string target, CancellationToken ct)
    {
        using IServiceScope scope = scopeFactory.CreateScope();
        await using KeywardDbContext db = await scope.ServiceProvider
            .GetRequiredService<IDbContextFactory<KeywardDbContext>>().CreateDbContextAsync(ct).ConfigureAwait(false);

        var canary = await db.KekCanaries.FirstOrDefaultAsync(ct).ConfigureAwait(false);
        if (canary is null || string.Equals(canary.KekId, target, StringComparison.Ordinal))
        {
            return false;
        }

        byte[] plain;
        try
        {
            plain = await kek.UnwrapAsync(canary.Wrapped, canary.KekId, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is CryptographicException or InvalidOperationException)
        {
            logger?.LogWarning(
                "KEYWARD: the key-ownership canary (KEK {KekId}) cannot be opened by this key ring and was left as it is.",
                canary.KekId);
            return false;
        }

        try
        {
            var entry = db.Entry(canary);
            entry.Property(c => c.Wrapped).CurrentValue = await kek.WrapAsync(plain, ct).ConfigureAwait(false);
            entry.Property(c => c.KekId).CurrentValue = target;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }

        await db.SaveChangesAsync(ct).ConfigureAwait(false);
        return true;
    }

    private async Task<EncryptedValue> RewrapAsync(EncryptedValue value, CancellationToken ct)
    {
        byte[] dek = await kek.UnwrapAsync(value.WrappedDek, value.KekId, ct).ConfigureAwait(false);
        try
        {
            byte[] wrapped = await kek.WrapAsync(dek, ct).ConfigureAwait(false);
            return value with { WrappedDek = wrapped, KekId = kek.KekId };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }
    }

    private sealed record Pending(string Kind, Guid Id, Guid? TenantId, Guid? OwnerUserId);
}
