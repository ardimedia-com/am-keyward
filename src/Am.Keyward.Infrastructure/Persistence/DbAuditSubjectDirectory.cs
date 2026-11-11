using System.Text.Json;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Audit;
using Am.Keyward.Core.Domain.ValueObjects;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;

namespace Am.Keyward.Infrastructure.Persistence;

/// <summary>
/// Crypto-shredding directory: maps an actor to a stable opaque pseudonym and stores that actor's PII
/// encrypted under a per-subject DEK (envelope, KEK-wrapped). Erasure clears the ciphertext so the PII is
/// irrecoverable while the audit chain keeps the pseudonym. The db-parametric
/// <see cref="ResolvePseudonymAsync(KeywardDbContext, string?, AuditSubjectPii, CancellationToken)"/>
/// stages a newly-created subject on the CALLER's unit of work, so it is persisted by the caller's
/// SaveChanges together with the audit entry that references it; the port methods run on the scope's shared
/// context (endpoint semantics).
/// <para>
/// A new pseudonym is created with ONE insert-if-absent statement (under an update/range lock) on its OWN short-lived
/// context and connection, committed at once — not staged for the caller's SaveChanges and never part of the caller's
/// transaction: two concurrent first audits of the same new actor must end in one pseudonym (the filtered unique index
/// on <c>SubjectReference</c> over live rows enforces it too), and a caller's transaction must not keep a range lock on
/// this table while it waits for the audit-chain lock. A pseudonym whose audit entry then fails to save is harmless — it
/// is reused by the actor's next audit.
/// </para>
/// </summary>
public sealed class DbAuditSubjectDirectory(
    KeywardDbContext db,
    IDbContextFactory<KeywardDbContext> dbFactory,
    ISecretBackend backend,
    IClock clock) : IAuditSubjectDirectory
{
    private const int AlgVersion = 1;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public ValueTask<Guid?> ResolvePseudonymAsync(string? subjectReference, AuditSubjectPii pii, CancellationToken ct = default) =>
        ResolvePseudonymAsync(db, subjectReference, pii, ct);

    public async ValueTask<Guid?> ResolvePseudonymAsync(
        KeywardDbContext target, string? subjectReference, AuditSubjectPii pii, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(subjectReference))
        {
            return null;
        }

        var reference = subjectReference.Trim();

        // Reuse an existing pseudonym: check entities already staged in this unit of work first (a single
        // SaveChanges may append several events for the same new actor), then the database.
        var staged = target.ChangeTracker.Entries<AuditSubject>()
            .Select(e => e.Entity)
            .FirstOrDefault(s => s.SubjectReference == reference && !s.IsErased);
        if (staged is not null)
        {
            return staged.Id;
        }

        if (await FindLiveAsync(target, reference, ct).ConfigureAwait(false) is { } existing)
        {
            return existing;
        }

        var pseudonymId = Guid.NewGuid();
        var aad = Aad.ForAuditSubjectPii(pseudonymId, AlgVersion);
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(pii, Json);
        EncryptedValue encrypted;
        try
        {
            encrypted = await backend.ProtectAsync(plaintext, aad, ct).ConfigureAwait(false);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(plaintext);
        }

        // Same JSON shape as the EncryptedPii value converter of KeywardDbContext (web defaults).
        var encryptedJson = JsonSerializer.Serialize(encrypted, Json);
        var createdAt = clock.UtcNow;
        await using var own = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        try
        {
            await own.Database.ExecuteSqlInterpolatedAsync($@"
                INSERT INTO [amkeyward].[AuditSubjects] ([Id], [SubjectReference], [EncryptedPii], [CreatedAt], [ErasedAt])
                SELECT {pseudonymId}, {reference}, {encryptedJson}, {createdAt}, NULL
                WHERE NOT EXISTS (
                    SELECT 1 FROM [amkeyward].[AuditSubjects] WITH (UPDLOCK, HOLDLOCK)
                    WHERE [SubjectReference] = {reference} AND [ErasedAt] IS NULL);", ct).ConfigureAwait(false);
        }
        catch (SqlException ex) when (ex.Number is 2601 or 2627)
        {
            // A concurrent writer created it between our check and our insert — use theirs.
        }

        return await FindLiveAsync(own, reference, ct).ConfigureAwait(false)
            ?? throw new InvalidOperationException("The audit pseudonym could not be created.");
    }

    private static Task<Guid?> FindLiveAsync(KeywardDbContext target, string reference, CancellationToken ct) =>
        target.AuditSubjects.AsNoTracking()
            .Where(s => s.SubjectReference == reference && s.ErasedAt == null)
            .Select(s => (Guid?)s.Id)
            .FirstOrDefaultAsync(ct);

    public async Task<AuditSubjectPii?> TryReadPiiAsync(Guid pseudonymId, CancellationToken ct = default)
    {
        var subject = await db.AuditSubjects
            .AsNoTracking()
            .FirstOrDefaultAsync(s => s.Id == pseudonymId, ct)
            .ConfigureAwait(false);
        if (subject?.EncryptedPii is null)
        {
            return null;
        }

        var aad = Aad.ForAuditSubjectPii(pseudonymId, subject.EncryptedPii.AlgVersion);
        var plaintext = await backend.UnprotectAsync(subject.EncryptedPii, aad, ct).ConfigureAwait(false);
        return JsonSerializer.Deserialize<AuditSubjectPii>(plaintext, Json);
    }

    public async Task<int> EraseAsync(string subjectReference, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(subjectReference))
        {
            return 0;
        }

        var reference = subjectReference.Trim();

        // Includes the duplicates the Review3DataIntegrity migration set aside as «<reference>#<id>» (two live
        // pseudonyms of one actor, created by a race before the unique index existed) — erasure must reach them too.
        var setAside = reference + "#";
        var subjects = await db.AuditSubjects
            .Where(s => (s.SubjectReference == reference || s.SubjectReference.StartsWith(setAside)) && s.ErasedAt == null)
            .ToListAsync(ct)
            .ConfigureAwait(false);

        foreach (var subject in subjects)
        {
            subject.Erase(clock.UtcNow);
        }

        if (subjects.Count > 0)
        {
            await db.SaveChangesAsync(ct).ConfigureAwait(false);
        }

        return subjects.Count;
    }
}
