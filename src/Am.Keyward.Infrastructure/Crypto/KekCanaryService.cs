using System.Security.Cryptography;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Domain.KeyCustody;
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

    private string Describe(KekCanary canary, string reason) =>
        $"This installation holds key '{kek.KekId}', but the database was sealed by key '{canary.KekId}' "
        + $"(written {canary.CreatedAt:yyyy-MM-dd HH:mm} UTC by {canary.CreatedBy}): {reason}. "
        + "Either point this installation at the key that owns the data (restore it from the escrow), or "
        + "point it at its own database.";
}
