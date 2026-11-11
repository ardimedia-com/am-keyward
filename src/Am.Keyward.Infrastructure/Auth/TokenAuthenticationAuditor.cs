using System.Collections.Concurrent;
using System.Net;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Am.Keyward.Infrastructure.Auth;

/// <summary>
/// Leaves a trace of a refused agent or app token: a log line always, and — when the presented prefix identified a
/// token record, so the tenant is known — an entry in that tenant's audit chain (<see cref="AuditAction.Login"/> on
/// the token, attributed to the token kind, with the reason). A token that names no record (junk, a typo, a guess)
/// is only logged: it has no tenant chain, and writing one entry per guess would let anyone grow the chain.
/// The presented token is never logged or stored.
/// <para>
/// The entry is written in its OWN scope with the token's tenant and actor, so the refused request's ambient scope
/// is never changed. Best-effort: a failing audit write is logged and never turns a 401 into a 500.
/// </para>
/// <para>
/// One entry per token and reason per <see cref="AuditInterval"/>: a deployed service that keeps retrying with an
/// expired or revoked token would otherwise add an entry on every attempt. Repeats within the interval are logged
/// at debug level only.
/// </para>
/// </summary>
public sealed class TokenAuthenticationAuditor(IServiceScopeFactory scopeFactory, IClock clock, ILogger<TokenAuthenticationAuditor> logger)
{
    /// <summary>How long a recorded refusal of the same token for the same reason is not recorded again.</summary>
    public static readonly TimeSpan AuditInterval = TimeSpan.FromHours(1);

    private const int MaxRemembered = 10_000;

    private readonly ConcurrentDictionary<(Guid TokenId, TokenAuthenticationFailure Failure), DateTimeOffset> lastAudited = new();

    /// <summary>The audit resource type of an agent token.</summary>
    public const string AgentTokenResource = "AgentToken";

    /// <summary>The audit resource type of an app (software-client) token.</summary>
    public const string SoftwareClientTokenResource = "SoftwareClientToken";

    /// <summary>The audit reason prefix of a refused authentication.</summary>
    public const string RefusedReasonPrefix = "Authentication refused: ";

    /// <summary>Records one refused authentication (see the class remarks for what is written where).</summary>
    public async Task RecordRefusalAsync(
        ActorKind tokenKind, TokenAuthenticationFailure failure, Guid? tokenId, Guid? tenantId, IPAddress? clientIp, CancellationToken ct)
    {
        var address = clientIp?.ToString() ?? "unknown address";
        if (tokenId is not { } id || tenantId is not { } tenant)
        {
            logger.LogDebug("KEYWARD: {TokenKind} token refused ({Reason}) from {ClientIp}.", tokenKind, failure, address);
            return;
        }

        if (!ShouldAudit(id, failure))
        {
            logger.LogDebug("KEYWARD: {TokenKind} token {TokenId} refused again ({Reason}) from {ClientIp}.", tokenKind, id, failure, address);
            return;
        }

        logger.LogWarning("KEYWARD: {TokenKind} token {TokenId} refused ({Reason}) from {ClientIp}.", tokenKind, id, failure, address);

        try
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var services = scope.ServiceProvider;
            services.GetRequiredService<ITenantScopeSetter>().SetTenant(tenant);
            services.GetRequiredService<IActorScopeSetter>().SetActor(tokenKind, id);

            await using var db = await services.GetRequiredService<IDbContextFactory<KeywardDbContext>>()
                .CreateDbContextAsync(ct).ConfigureAwait(false);
            var resource = tokenKind == ActorKind.Agent ? AgentTokenResource : SoftwareClientTokenResource;
            await services.GetRequiredService<DbAuditSink>().AppendAsync(
                db,
                new AuditRequest(tenant, AuditAction.Login, resource, id, ActorUserId: null, Reason: $"{RefusedReasonPrefix}{failure} from {address}"),
                ct).ConfigureAwait(false);
            await db.SaveChangesAsync(ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(ex, "KEYWARD: the refused authentication of {TokenKind} token {TokenId} could not be audited.", tokenKind, id);
        }
    }

    // Atomic per (token, reason): of two concurrent refusals only one wins the slot.
    private bool ShouldAudit(Guid tokenId, TokenAuthenticationFailure failure)
    {
        var now = clock.UtcNow;
        if (lastAudited.Count > MaxRemembered)
        {
            foreach (var stale in lastAudited.Where(e => now - e.Value >= AuditInterval).Select(e => e.Key).ToList())
            {
                lastAudited.TryRemove(stale, out _);
            }
        }

        var key = (tokenId, failure);
        while (true)
        {
            if (!lastAudited.TryGetValue(key, out var previous))
            {
                if (lastAudited.TryAdd(key, now))
                {
                    return true;
                }

                continue;
            }

            if (now - previous < AuditInterval)
            {
                return false;
            }

            if (lastAudited.TryUpdate(key, now, previous))
            {
                return true;
            }
        }
    }
}
