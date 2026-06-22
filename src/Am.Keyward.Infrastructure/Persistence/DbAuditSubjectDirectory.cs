using System.Text.Json;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Audit;
using Microsoft.EntityFrameworkCore;

namespace Am.Keyward.Infrastructure.Persistence;

/// <summary>
/// Crypto-shredding directory: maps an actor to a stable opaque pseudonym and stores that actor's PII
/// encrypted under a per-subject DEK (envelope, KEK-wrapped). Erasure clears the ciphertext so the PII is
/// irrecoverable while the audit chain keeps the pseudonym. Shares the request's <see cref="KeywardDbContext"/>
/// so a newly-created subject is persisted by the caller's SaveChanges, in the same unit of work as the
/// audit entry that references it.
/// </summary>
public sealed class DbAuditSubjectDirectory(KeywardDbContext db, ISecretBackend backend, IClock clock) : IAuditSubjectDirectory
{
    private const int AlgVersion = 1;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public async ValueTask<Guid?> ResolvePseudonymAsync(string? subjectReference, AuditSubjectPii pii, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(subjectReference))
        {
            return null;
        }

        var reference = subjectReference.Trim();

        // Reuse an existing pseudonym: check entities already staged in this unit of work first (a single
        // SaveChanges may append several events for the same new actor), then the database.
        var staged = db.ChangeTracker.Entries<AuditSubject>()
            .Select(e => e.Entity)
            .FirstOrDefault(s => s.SubjectReference == reference && !s.IsErased);
        if (staged is not null)
        {
            return staged.Id;
        }

        var existing = await db.AuditSubjects
            .FirstOrDefaultAsync(s => s.SubjectReference == reference && s.ErasedAt == null, ct)
            .ConfigureAwait(false);
        if (existing is not null)
        {
            return existing.Id;
        }

        var pseudonymId = Guid.NewGuid();
        var aad = Aad.ForAuditSubjectPii(pseudonymId, AlgVersion);
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(pii, Json);
        var encrypted = await backend.ProtectAsync(plaintext, aad, ct).ConfigureAwait(false);
        db.AuditSubjects.Add(new AuditSubject(pseudonymId, reference, encrypted, clock.UtcNow));
        return pseudonymId;
    }

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
        var subjects = await db.AuditSubjects
            .Where(s => s.SubjectReference == reference && s.ErasedAt == null)
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
