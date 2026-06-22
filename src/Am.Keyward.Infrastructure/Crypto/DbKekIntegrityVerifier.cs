using Am.Keyward.Core.Abstractions;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Am.Keyward.Infrastructure.Crypto;

/// <summary>
/// Backup/restore consistency job. Scans every persisted encrypted slot (software secret versions and
/// human vault item versions) and checks that the KEK id its DEK was wrapped under is still resolvable by
/// the current <see cref="IKekProvider"/>. An unresolvable id means the database was restored without its
/// matching KEK store, or a KEK version was retired before its rows were re-wrapped — either way those
/// values would be undecryptable, which this surfaces before they are needed.
/// </summary>
/// <remarks>
/// Runs installation-wide, so it deliberately ignores the tenant query filter and must execute with a
/// database login allowed to read all rows (the least-privilege runtime login is hidden from cross-tenant
/// rows by row-level security). It checks KEK-id resolvability only — it does not unwrap each DEK, which
/// would cost a KEK round-trip per row.
/// </remarks>
public sealed class DbKekIntegrityVerifier(KeywardDbContext db, IKekProvider kek) : IKekIntegrityVerifier
{
    public async Task<KekIntegrityReport> VerifyAsync(CancellationToken ct = default)
    {
        long checkedCount = 0;
        var issues = new List<KekIntegrityIssue>();

        // Encrypted is a JSON-converted scalar column, so the KEK id can't be projected server-side; stream
        // (Id, envelope) and read the id in memory. Only ciphertext metadata is materialized — no plaintext.
        var secretSlots = db.SecretVersions
            .IgnoreQueryFilters()
            .AsNoTracking()
            .Select(v => new { v.Id, v.Encrypted })
            .AsAsyncEnumerable();
        await foreach (var slot in secretSlots.WithCancellation(ct).ConfigureAwait(false))
        {
            checkedCount++;
            if (!kek.CanResolve(slot.Encrypted.KekId))
            {
                issues.Add(new KekIntegrityIssue("SecretVersion", slot.Id, slot.Encrypted.KekId));
            }
        }

        var itemSlots = db.VaultItemVersions
            .IgnoreQueryFilters()
            .AsNoTracking()
            .Select(v => new { v.Id, v.Encrypted })
            .AsAsyncEnumerable();
        await foreach (var slot in itemSlots.WithCancellation(ct).ConfigureAwait(false))
        {
            checkedCount++;
            if (!kek.CanResolve(slot.Encrypted.KekId))
            {
                issues.Add(new KekIntegrityIssue("VaultItemVersion", slot.Id, slot.Encrypted.KekId));
            }
        }

        return new KekIntegrityReport(checkedCount, issues);
    }
}
