using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Domain;
using Microsoft.EntityFrameworkCore;

namespace Am.Keyward.Infrastructure.Persistence;

/// <summary>
/// <see cref="IKeywardAccountDeletion"/>: marks the user deleted (which disables them), revokes their agent tokens and
/// audits the deletion. The personal vaults are removed later by <see cref="KeywardRetentionBackgroundService"/>, once
/// the retention period has passed. The <c>Users</c> and <c>AgentTokens</c> tables are installation-global, so — like
/// the identity binder — this needs no tenant scope; it runs from the host's admin action, not as the user.
/// </summary>
public sealed class KeywardAccountDeletion(KeywardDbContext db, IClock clock, DbAuditSink audit) : IKeywardAccountDeletion
{
    public async Task<bool> DeleteAccountAsync(string externalId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(externalId);

        var user = await db.Users
            .FirstOrDefaultAsync(u => u.Issuer == null && u.ExternalId == externalId.Trim(), cancellationToken)
            .ConfigureAwait(false);
        if (user is null)
        {
            return false;
        }

        var now = clock.UtcNow;
        var firstDeletion = !user.IsDeleted;
        user.MarkDeleted(now);
        if (firstDeletion)
        {
            // System actor, personal chain: the deletion is an administrative act on the account, not the user's own.
            await audit.AppendAsync(db, new AuditRequest(null, AuditAction.Delete, "UserAccount", user.Id, null), cancellationToken).ConfigureAwait(false);
        }

        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        // A deleted user keeps no working agent token — each is revoked for good, like on a plain disable.
        await db.AgentTokens
            .Where(t => t.UserId == user.Id && t.RevokedAt == null)
            .ExecuteUpdateAsync(set => set.SetProperty(t => t.RevokedAt, (DateTimeOffset?)now), cancellationToken)
            .ConfigureAwait(false);
        return true;
    }
}
