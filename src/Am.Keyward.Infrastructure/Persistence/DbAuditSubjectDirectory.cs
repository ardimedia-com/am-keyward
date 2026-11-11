using System.Security.Cryptography;
using System.Text.Json;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Audit;
using Am.Keyward.Core.Domain.ValueObjects;
using Microsoft.EntityFrameworkCore;

namespace Am.Keyward.Infrastructure.Persistence;

/// <summary>
/// Crypto-shredding directory: maps an actor to a stable opaque pseudonym and stores that actor's PII
/// encrypted under a per-subject DEK (envelope, KEK-wrapped). Erasure clears the ciphertext so the PII is
/// irrecoverable while the audit chain keeps the pseudonym. The db-parametric
/// <see cref="ResolvePseudonymAsync(KeywardDbContext, string?, AuditSubjectPii, CancellationToken)"/> looks the subject
/// up on the CALLER's context; the port methods run on the scope's shared context (endpoint semantics).
/// <para>
/// A new pseudonym is inserted on its OWN short-lived context and connection and committed at once — never staged for
/// the caller's SaveChanges, never part of the caller's transaction. Two concurrent first audits of the same new actor
/// end in one pseudonym: the filtered unique index on <c>SubjectReference</c> (live rows) rejects the second insert,
/// which then uses the winner's. A pseudonym whose audit entry fails to save afterwards is harmless — the actor's next
/// audit reuses it.
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

        // Its own context: committed at once, outside any transaction of the caller. A concurrent first audit of the same
        // actor loses on the filtered unique index — then the winner's pseudonym is used. (A plain insert, no lock hints:
        // range locks taken to pre-empt the race deadlocked concurrent inserts of DIFFERENT actors on a small table.)
        await using var own = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        own.AuditSubjects.Add(new AuditSubject(pseudonymId, reference, encrypted, clock.UtcNow));
        try
        {
            await own.SaveChangesAsync(ct).ConfigureAwait(false);
            return pseudonymId;
        }
        catch (DbUpdateException ex) when (ex.IsUniqueViolation())
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
        try
        {
            return JsonSerializer.Deserialize<AuditSubjectPii>(plaintext, Json);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
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
