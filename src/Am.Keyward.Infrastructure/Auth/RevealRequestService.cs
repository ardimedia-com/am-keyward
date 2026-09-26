using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Agent;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Am.Keyward.Infrastructure.Auth;

/// <summary>
/// The reveal flow (see <see cref="IRevealRequestService"/>). Requests are tenant data (query filter and
/// row-level security); every transition is serialized by the request row version, and the value itself is read
/// only after the request is marked consumed, so a value is handed out at most once.
/// </summary>
public sealed class RevealRequestService(
    IDbContextFactory<KeywardDbContext> dbFactory,
    IClock clock,
    ICurrentUser currentUser,
    ICurrentTenant tenant,
    IVaultService vaults,
    DbAuditSink audit,
    IEnumerable<IKeywardAlertPresenter> presenters,
    ILogger<RevealRequestService> logger) : IRevealRequestService
{
    private const string ResourceType = "RevealRequest";

    public async Task<RevealRequestState> RequestAsync(Guid tokenId, Guid itemId, RevealField field, string reason, CancellationToken ct = default)
    {
        var (userId, tenantId) = RequireScope();

        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var token = await db.AgentTokens.AsNoTracking()
            .FirstOrDefaultAsync(t => t.Id == tokenId && t.UserId == userId && t.TenantId == tenantId, ct).ConfigureAwait(false)
            ?? throw new UnauthorizedAccessException("The agent token does not act for the current user.");

        var item = await db.VaultItems.AsNoTracking()
            .Where(i => i.Id == itemId)
            .Select(i => new { i.Id, i.VaultId, i.Type, i.Name })
            .FirstOrDefaultAsync(ct).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Item {itemId} not found.");

        var fits = item.Type == ItemType.Login ? field is RevealField.Password or RevealField.Note : field == RevealField.Value;
        if (!fits)
        {
            throw new ArgumentException(item.Type == ItemType.Login
                ? "A Login reveals its password or its note."
                : $"A {item.Type} reveals its value.");
        }

        var request = new RevealRequest(Guid.NewGuid(), tenantId, tokenId, userId, itemId, field, reason, clock.UtcNow);
        db.RevealRequests.Add(request);
        await audit.AppendAsync(db, new AuditRequest(tenantId, AuditAction.RevealRequested, ResourceType, request.Id, userId, request.Reason), ct).ConfigureAwait(false);
        await db.SaveChangesAsync(ct).ConfigureAwait(false);

        await NotifyAsync(tenantId, userId, request, token.Name, item.VaultId, item.Name, ct).ConfigureAwait(false);
        return Map(request, clock.UtcNow);
    }

    public async Task<RevealRequestState?> GetAsync(Guid tokenId, Guid requestId, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var request = await db.RevealRequests.AsNoTracking()
            .FirstOrDefaultAsync(r => r.Id == requestId && r.TokenId == tokenId, ct).ConfigureAwait(false);
        return request is null ? null : Map(request, clock.UtcNow);
    }

    public async Task<RevealConsumeResult?> ConsumeAsync(Guid tokenId, Guid requestId, CancellationToken ct = default)
    {
        var (userId, _) = RequireScope();
        var now = clock.UtcNow;

        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var request = await db.RevealRequests
            .FirstOrDefaultAsync(r => r.Id == requestId && r.TokenId == tokenId && r.UserId == userId, ct).ConfigureAwait(false);
        if (request is null)
        {
            return null;
        }

        var status = request.StatusAt(now);
        if (status != RevealRequestStatus.Approved)
        {
            return new RevealConsumeResult(status, null);
        }

        // Consumed BEFORE the value is read: if two calls race, the row version lets exactly one through, and a
        // failure after this point loses the value rather than handing it out twice.
        request.Consume(now);
        try
        {
            await db.SaveChangesAsync(ct).ConfigureAwait(false);
        }
        catch (DbUpdateConcurrencyException)
        {
            return new RevealConsumeResult(RevealRequestStatus.Consumed, null);
        }

        var value = await vaults.RevealFieldAsync(userId, request.ItemId, request.Field, request.Reason, ct).ConfigureAwait(false);
        return new RevealConsumeResult(RevealRequestStatus.Consumed, value);
    }

    public async Task<IReadOnlyList<PendingRevealRequest>> ListPendingAsync(Guid userId, Guid tenantId, CancellationToken ct = default)
    {
        EnsureScope(userId, tenantId);
        var now = clock.UtcNow;

        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var requests = await db.RevealRequests.AsNoTracking()
            .Where(r => r.UserId == userId && r.Status == RevealRequestStatus.Pending && r.ExpiresAt > now)
            .OrderBy(r => r.CreatedAt)
            .ToListAsync(ct).ConfigureAwait(false);
        if (requests.Count == 0)
        {
            return [];
        }

        var tokenIds = requests.Select(r => r.TokenId).Distinct().ToList();
        var itemIds = requests.Select(r => r.ItemId).Distinct().ToList();
        var tokenNames = await db.AgentTokens.AsNoTracking()
            .Where(t => tokenIds.Contains(t.Id))
            .ToDictionaryAsync(t => t.Id, t => t.Name, ct).ConfigureAwait(false);
        var items = await db.VaultItems.AsNoTracking()
            .Where(i => itemIds.Contains(i.Id))
            .Join(db.Vaults, i => i.VaultId, v => v.Id, (i, v) => new { i.Id, ItemName = i.Name, VaultName = v.Name })
            .ToDictionaryAsync(x => x.Id, ct).ConfigureAwait(false);

        return requests
            .Where(r => items.ContainsKey(r.ItemId))
            .Select(r => new PendingRevealRequest(
                r.Id, tokenNames.GetValueOrDefault(r.TokenId, "?"), items[r.ItemId].VaultName, items[r.ItemId].ItemName,
                r.Field, r.Reason, r.CreatedAt, r.ExpiresAt))
            .ToList();
    }

    public Task ApproveAsync(Guid userId, Guid tenantId, Guid requestId, CancellationToken ct = default) =>
        DecideAsync(userId, tenantId, requestId, approve: true, ct);

    public Task RejectAsync(Guid userId, Guid tenantId, Guid requestId, CancellationToken ct = default) =>
        DecideAsync(userId, tenantId, requestId, approve: false, ct);

    private async Task DecideAsync(Guid userId, Guid tenantId, Guid requestId, bool approve, CancellationToken ct)
    {
        EnsureScope(userId, tenantId);
        var now = clock.UtcNow;

        await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        var request = await db.RevealRequests
            .FirstOrDefaultAsync(r => r.Id == requestId, ct).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Reveal request {requestId} not found.");

        if (approve) { request.Approve(userId, now); } else { request.Reject(userId, now); }

        await audit.AppendAsync(db, new AuditRequest(
            tenantId, approve ? AuditAction.RevealApproved : AuditAction.RevealRejected, ResourceType, request.Id, userId), ct).ConfigureAwait(false);
        try
        {
            await db.SaveChangesAsync(ct).ConfigureAwait(false);
        }
        catch (DbUpdateConcurrencyException)
        {
            throw new InvalidOperationException("The reveal request was decided in the meantime.");
        }
    }

    // Best-effort: the request is valid without the notice, and a delivery problem must not fail the agent call.
    private async Task NotifyAsync(Guid tenantId, Guid userId, RevealRequest request, string tokenName, Guid vaultId, string itemName, CancellationToken ct)
    {
        if (!presenters.Any())
        {
            return;
        }

        try
        {
            await using var db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
            var externalId = await db.Users.AsNoTracking().Where(u => u.Id == userId).Select(u => u.ExternalId).FirstOrDefaultAsync(ct).ConfigureAwait(false);
            var vaultName = await db.Vaults.AsNoTracking().Where(v => v.Id == vaultId).Select(v => v.Name).FirstOrDefaultAsync(ct).ConfigureAwait(false);
            if (externalId is null)
            {
                return;
            }

            var line = new KeywardRevealRequestLine(request.Id, tokenName, vaultName ?? "?", itemName, request.Field, request.Reason, request.ExpiresAt);
            foreach (var presenter in presenters)
            {
                await presenter.NotifyRevealRequestAsync(tenantId, new KeywardAlertRecipient(userId, externalId), line, ct).ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Could not notify user {UserId} about reveal request {RequestId}.", userId, request.Id);
        }
    }

    private static RevealRequestState Map(RevealRequest r, DateTimeOffset now) => new(r.Id, r.ItemId, r.Field, r.StatusAt(now), r.ExpiresAt, r.ConsumeBy);

    private (Guid UserId, Guid TenantId) RequireScope() =>
        (currentUser.UserId ?? throw new UnauthorizedAccessException("No user in scope."),
         tenant.TenantId ?? throw new UnauthorizedAccessException("No tenant in scope."));

    private void EnsureScope(Guid userId, Guid tenantId)
    {
        if (currentUser.UserId != userId || tenant.TenantId != tenantId)
        {
            throw new UnauthorizedAccessException("Scope mismatch: reveal requests are decided only by their own user, in their tenant.");
        }
    }
}
