using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain.Agent;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Am.Keyward.Infrastructure.Monitoring;

/// <summary>
/// Reminds the owner of an AI agent token that it expires soon, on the <see cref="ExpiryNoticePolicy"/> schedule
/// (30/20/10 days ahead, then daily from 9 days), through <see cref="IKeywardAlertPresenter.NotifyAgentTokenExpiryAsync"/>.
/// Only the owner can extend a token, so the notice goes to that user alone — never to the administrators.
/// </summary>
public sealed class AgentTokenExpiryNotificationService(
    IServiceScopeFactory scopeFactory,
    IClock clock,
    ILogger<AgentTokenExpiryNotificationService> logger) : BackgroundService
{
    private static readonly TimeSpan CheckInterval = TimeSpan.FromHours(1);
    private static readonly TimeSpan StartupDelay = TimeSpan.FromMinutes(2);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await Task.Delay(StartupDelay, stoppingToken).ConfigureAwait(false);
            using var timer = new PeriodicTimer(CheckInterval);
            do
            {
                try
                {
                    await NotifyDueTokensAsync(stoppingToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Agent-token expiry notification run failed.");
                }
            }
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
            // Host shutting down — expected.
        }
    }

    /// <summary>One run: finds the due tokens and notifies their owners. Returns how many tokens were announced.</summary>
    internal async Task<int> NotifyDueTokensAsync(CancellationToken ct)
    {
        var now = clock.UtcNow;

        // The token table is installation-global (looked up before a tenant is known), so discovery needs no scope.
        using var scope = scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
        var horizon = now.AddDays(ExpiryNoticePolicy.WindowDays + 1);
        var candidates = await db.AgentTokens
            .Where(t => t.RevokedAt == null && t.ExpiresAt > now && t.ExpiresAt <= horizon)
            .ToListAsync(ct)
            .ConfigureAwait(false);
        var due = candidates
            .Select(t => (Token: t, DaysLeft: ExpiryNoticePolicy.DaysLeft(now, t.ExpiresAt)))
            .Where(x => ExpiryNoticePolicy.IsDue(x.DaysLeft, x.Token.LastExpiryNoticeDaysLeft))
            .ToList();

        var announced = 0;
        foreach (var owner in due.GroupBy(x => (x.Token.TenantId, x.Token.UserId)))
        {
            var group = owner.ToList();
            try
            {
                if (await NotifyOwnerAsync(owner.Key.TenantId, owner.Key.UserId, group, ct).ConfigureAwait(false))
                {
                    foreach (var (token, daysLeft) in group)
                    {
                        token.MarkExpiryNoticeSent(daysLeft);
                    }

                    await db.SaveChangesAsync(ct).ConfigureAwait(false);
                    announced += group.Count;
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Agent-token expiry notice failed for user {UserId}; continuing with the next.", owner.Key.UserId);
            }
        }

        return announced;
    }

    private async Task<bool> NotifyOwnerAsync(
        Guid tenantId, Guid userId, IReadOnlyList<(AgentToken Token, int DaysLeft)> due, CancellationToken ct)
    {
        using var scope = scopeFactory.CreateScope();
        scope.ServiceProvider.GetRequiredService<ITenantScopeSetter>().SetTenant(tenantId);
        if (scope.ServiceProvider.GetService<IKeywardAlertPresenter>() is not { } presenter)
        {
            return false; // pending until a host registers a presenter
        }

        var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
        var owner = await db.Users.AsNoTracking()
            .Where(u => u.Id == userId && u.DisabledAt == null)
            .Select(u => new KeywardAlertRecipient(u.Id, u.ExternalId))
            .FirstOrDefaultAsync(ct)
            .ConfigureAwait(false);
        if (owner is null)
        {
            return false;
        }

        var lines = due
            .OrderBy(x => x.DaysLeft)
            .Select(x => new KeywardAgentTokenExpiryLine(x.Token.Id, x.Token.Name, x.DaysLeft, x.Token.ExpiresAt))
            .ToList();
        return await presenter.NotifyAgentTokenExpiryAsync(tenantId, owner, lines, ct).ConfigureAwait(false) > 0;
    }
}
