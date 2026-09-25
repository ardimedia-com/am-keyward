using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Domain;
using Microsoft.EntityFrameworkCore;

namespace Am.Keyward.Infrastructure.Persistence;

/// <summary>
/// The single software-operator check (applications, environments, secrets, client tokens, heartbeat
/// monitoring): a system admin, a software manager, OR a tenant admin of the tenant.
/// </summary>
internal static class SoftwareOperatorGuard
{
    /// <summary>Whether <paramref name="actorUserId"/> is a software operator of the tenant (false for null).</summary>
    public static async Task<bool> IsOperatorAsync(KeywardDbContext db, Guid tenantId, Guid? actorUserId, CancellationToken ct)
    {
        if (actorUserId is not { } actor)
        {
            return false;
        }

        return await db.Users.AnyAsync(u => u.Id == actor && (u.IsSystemAdmin || u.IsSoftwareManager), ct).ConfigureAwait(false)
            || await db.TenantMemberships.AnyAsync(
                m => m.TenantId == tenantId && m.UserId == actor && m.Role == TenantRole.TenantAdmin, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Throws unless the acting user is a software operator. The actor is the explicit
    /// <paramref name="actorUserId"/>, else the ambient <see cref="ICurrentUser"/>: an HTTP caller that omits the
    /// actor is still checked as the signed-in user. Only a call with NO user at all — seeding and background
    /// jobs, which run without a request — is treated as a trusted system caller.
    /// </summary>
    public static async Task EnsureOperatorAsync(
        KeywardDbContext db, Guid tenantId, Guid? actorUserId, ICurrentUser currentUser, string deniedMessage, CancellationToken ct)
    {
        var actor = actorUserId ?? currentUser.UserId;
        if (actor is null)
        {
            return;
        }

        if (!await IsOperatorAsync(db, tenantId, actor, ct).ConfigureAwait(false))
        {
            throw new UnauthorizedAccessException(deniedMessage);
        }
    }
}
