using System.Security.Cryptography;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Domain.KeyCustody;
using Am.Keyward.Core.Domain.ValueObjects;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Am.Keyward.Infrastructure.Crypto;

/// <summary>
/// Proves at startup that the key-encryption key this process holds is the key the database's stored values
/// were sealed with — by unwrapping a known plaintext that a previous start wrapped
/// (<see cref="KekCanary"/>). It answers the question directly instead of comparing stand-ins such as
/// machine names, key paths or the format-only <c>KekId</c>.
/// </summary>
public sealed class KekCanaryService(
    IDbContextFactory<KeywardDbContext> dbFactory,
    IKekProvider kek,
    IClock clock)
{
    /// <summary>
    /// The known plaintext: a fixed 32 bytes, derived deterministically so every installation of every
    /// version expects the very same value. Public knowledge by design — the check is about who can produce
    /// its ciphertext, not about hiding it.
    /// </summary>
    private static readonly byte[] Expected = SHA256.HashData("amkeyward-kek-canary-v1"u8);

    public async Task<(KekIntegrityStatus Status, string? Detail)> VerifyOrCreateAsync(
        string writtenBy, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);

        KekCanary? canary = await db.KekCanaries.AsNoTracking().FirstOrDefaultAsync(ct).ConfigureAwait(false);
        if (canary is null)
        {
            // No canary is not proof of a fresh database: it may be one that predates the canary, or a copy whose
            // canary row was lost. If it already holds values this key cannot open, writing a canary would hand
            // the data's ownership to the wrong key and silence every later check.
            string? foreign = await this.FindForeignCiphertextAsync(db, ct).ConfigureAwait(false);
            if (foreign is not null)
            {
                return (KekIntegrityStatus.Conflict,
                    $"This installation holds key '{kek.KekId}', but the database has no ownership canary and already "
                    + $"holds values this key cannot open ({foreign}). No canary was written. Either point this "
                    + "installation at the key that owns the data (restore it from the escrow), or point it at its own "
                    + "database.");
            }

            byte[] wrapped = await kek.WrapAsync(Expected, ct).ConfigureAwait(false);
            db.KekCanaries.Add(KekCanary.Create(kek.KekId, wrapped, clock.UtcNow, writtenBy));
            try
            {
                await db.SaveChangesAsync(ct).ConfigureAwait(false);
                return (KekIntegrityStatus.Created, $"Key '{kek.KekId}' now owns this database.");
            }
            catch (DbUpdateException)
            {
                // Two installations started at the same moment and both found no canary; the fixed primary
                // key turned the loser's insert into a duplicate. Re-read and verify against the winner's.
                db.ChangeTracker.Clear();
                canary = await db.KekCanaries.AsNoTracking().FirstOrDefaultAsync(ct).ConfigureAwait(false);
                if (canary is null)
                {
                    throw;
                }
            }
        }

        byte[] unwrapped;
        try
        {
            unwrapped = await kek.UnwrapAsync(canary.Wrapped, canary.KekId, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is CryptographicException or InvalidOperationException)
        {
            // Both shapes mean the same thing: an id this provider will not resolve, or an authentication
            // tag that does not verify under this key.
            return (KekIntegrityStatus.Conflict, Describe(canary, ex.Message));
        }

        bool matches = CryptographicOperations.FixedTimeEquals(unwrapped, Expected);
        CryptographicOperations.ZeroMemory(unwrapped);

        return matches
            ? (KekIntegrityStatus.Ok, null)
            : (KekIntegrityStatus.Conflict, Describe(canary, "the canary decrypted to an unexpected value"));
    }

    /// <summary>
    /// Trial-unwraps the data key of the NEWEST stored software-secret version and vault-item version (the newest
    /// is the one most likely written by the current key). Returns a description of the first one that does not
    /// open, or <c>null</c> when both open or none exist. Only the wrapped data key is touched — never a value —
    /// and the unwrapped data key is zeroed at once.
    ///
    /// <para>Reads across tenants: the caller runs it in a scope with the system read bypass
    /// (<see cref="Tenancy.SystemReadScope"/>), otherwise row-level security hides every version from a tenant-less
    /// scope and the probe finds nothing.</para>
    /// </summary>
    private async Task<string?> FindForeignCiphertextAsync(KeywardDbContext db, CancellationToken ct)
    {
        EncryptedValue? secret = await db.SecretVersions.IgnoreQueryFilters().AsNoTracking()
            .OrderByDescending(v => v.CreatedAt)
            .Select(v => v.Encrypted)
            .FirstOrDefaultAsync(ct).ConfigureAwait(false);
        if (secret is not null && !await this.OpensAsync(secret, ct).ConfigureAwait(false))
        {
            return $"a software-secret version sealed by key '{secret.KekId}'";
        }

        EncryptedValue? item = await db.VaultItemVersions.IgnoreQueryFilters().AsNoTracking()
            .OrderByDescending(v => v.CreatedAt)
            .Select(v => v.Encrypted)
            .FirstOrDefaultAsync(ct).ConfigureAwait(false);
        if (item is not null && !await this.OpensAsync(item, ct).ConfigureAwait(false))
        {
            return $"a vault-item version sealed by key '{item.KekId}'";
        }

        return null;
    }

    private async Task<bool> OpensAsync(EncryptedValue value, CancellationToken ct)
    {
        try
        {
            byte[] dek = await kek.UnwrapAsync(value.WrappedDek, value.KekId, ct).ConfigureAwait(false);
            CryptographicOperations.ZeroMemory(dek);
            return true;
        }
        catch (Exception ex) when (ex is CryptographicException or InvalidOperationException)
        {
            return false;
        }
    }

    private string Describe(KekCanary canary, string reason) =>
        $"This installation holds key '{kek.KekId}', but the database was sealed by key '{canary.KekId}' "
        + $"(written {canary.CreatedAt:yyyy-MM-dd HH:mm} UTC by {canary.CreatedBy}): {reason}. "
        + "Either point this installation at the key that owns the data (restore it from the escrow), or "
        + "point it at its own database.";
}
