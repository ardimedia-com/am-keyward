using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Domain.Audit;
using Microsoft.EntityFrameworkCore;

namespace Am.Keyward.Infrastructure.Persistence;

/// <summary>
/// Per-tenant hash-chained audit sink. It pseudonymizes the actor (via <see cref="DbAuditSubjectDirectory"/>,
/// so the chain stores an opaque, crypto-shreddable pseudonym instead of a user id) and stages an
/// <see cref="AuditEntry"/> on the caller's unit of work (persisted by the caller's SaveChanges): the port
/// method stages on the scope's shared context (endpoint semantics), while the db-parametric overload lets a
/// factory-based service stage on ITS per-operation context, so audit and business write still commit
/// atomically in one SaveChanges. The chain position (sequence) and hashes are assigned at commit by
/// <see cref="AuditChainInterceptor"/> under a per-chain lock — the single writer — so concurrent appends
/// cannot fork the chain or collide on a sequence number.
/// </summary>
public sealed class DbAuditSink(KeywardDbContext db, IClock clock, DbAuditSubjectDirectory subjects) : IAuditSink
{
    public ValueTask AppendAsync(AuditRequest request, CancellationToken ct = default) =>
        AppendAsync(db, request, ct);

    public async ValueTask AppendAsync(KeywardDbContext target, AuditRequest request, CancellationToken ct = default)
    {
        var pseudonymId = await ResolveActorAsync(target, request.ActorUserId, ct).ConfigureAwait(false);

        // Sequence + previous/current hash are filled in by AuditChainInterceptor at SaveChanges.
        target.AuditEntries.Add(new AuditEntry(
            Guid.NewGuid(), request.TenantId, sequence: 0, request.Action, request.ResourceType,
            request.ResourceId, pseudonymId, clock.UtcNow, AuditChainHash.GenesisHash, hash: string.Empty));
    }

    private async ValueTask<Guid?> ResolveActorAsync(KeywardDbContext target, Guid? actorUserId, CancellationToken ct)
    {
        if (actorUserId is not { } userId)
        {
            return null; // unattributed (e.g. a software-client read scoped only by token)
        }

        // The only actor PII Keyward holds is the display name (email lives in the host's identity store).
        var user = await target.Users
            .AsNoTracking()
            .FirstOrDefaultAsync(u => u.Id == userId, ct)
            .ConfigureAwait(false);
        var pii = new AuditSubjectPii(user?.DisplayName ?? "(unknown)", user?.ExternalId);
        return await subjects.ResolvePseudonymAsync(target, userId.ToString("D"), pii, ct).ConfigureAwait(false);
    }
}
