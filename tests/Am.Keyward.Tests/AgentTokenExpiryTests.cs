using System.Security.Cryptography;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain.Agent;
using Am.Keyward.Infrastructure;
using Am.Keyward.Infrastructure.Monitoring;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

namespace Am.Keyward.Tests;

/// <summary>
/// Decision T9 A (2026-10-02): an AI agent token can be extended without a new value, and its owner is reminded on
/// the 30/20/10/daily schedule before it expires.
/// </summary>
[TestClass]
public class AgentTokenExpiryTests
{
    [TestMethod, TestCategory("Integration")]
    public async Task Extending_keeps_the_value_and_the_owner_is_reminded_before_expiry()
    {
        var presenter = new CapturingPresenter();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddKeyward(TestConfig.ConnectionString, RandomNumberGenerator.GetBytes(32), "test-kek:v1");
        services.AddScoped<IKeywardAlertPresenter>(_ => presenter);
        await using var provider = services.BuildServiceProvider();
        using (var probe = provider.CreateScope())
        {
            if (!await probe.ServiceProvider.GetRequiredService<KeywardDbContext>().Database.CanConnectAsync())
            {
                Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
                return;
            }
        }

        var tenantId = Guid.NewGuid();
        var owner = Guid.NewGuid();
        await AgentApiTests.SeedTenantAsync(provider, tenantId, owner);

        IssuedAgentToken issued;
        using (var scope = AgentApiTests.ScopeFor(provider, tenantId, owner))
        {
            var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
            var vault = await vaults.CreateTenantVaultAsync(new CreateTenantVaultCommand(owner, tenantId, "KI-Tresor"));
            await vaults.SetAgentAccessAsync(owner, vault, allowed: true);
            issued = await scope.ServiceProvider.GetRequiredService<IAgentTokenService>().IssueAsync(new IssueAgentTokenCommand(
                owner, tenantId, "WUHARRY", AgentScopes.VaultList, [vault], ExpiresAt: DateTimeOffset.UtcNow.AddDays(5)));
        }

        // Five days left: due (daily from nine days on), sent to the owner, then not again for the same bucket.
        var job = new AgentTokenExpiryNotificationService(
            provider.GetRequiredService<IServiceScopeFactory>(), provider.GetRequiredService<IClock>(), NullLogger<AgentTokenExpiryNotificationService>.Instance);
        await job.NotifyDueTokensAsync(CancellationToken.None);
        var notice = presenter.Notices.Single(n => n.Recipient.UserId == owner);
        Assert.AreEqual("WUHARRY", notice.Lines.Single().TokenName);
        Assert.AreEqual(5, notice.Lines.Single().DaysLeft);
        presenter.Notices.Clear();
        await job.NotifyDueTokensAsync(CancellationToken.None);
        Assert.IsFalse(presenter.Notices.Any(n => n.Recipient.UserId == owner));

        // Extending keeps the value working and leaves the reminder window.
        using (var scope = AgentApiTests.ScopeFor(provider, tenantId, owner))
        {
            var until = await scope.ServiceProvider.GetRequiredService<IAgentTokenService>().ExtendAsync(owner, tenantId, issued.TokenId);
            Assert.IsGreaterThan(DateTimeOffset.UtcNow.AddDays(89), until);
        }

        using (var scope = provider.CreateScope())
        {
            var principal = await scope.ServiceProvider.GetRequiredService<IAgentAuthenticator>().AuthenticateAsync(issued.Token, System.Net.IPAddress.Loopback);
            Assert.AreEqual(issued.TokenId, principal!.TokenId);
            var token = await scope.ServiceProvider.GetRequiredService<KeywardDbContext>().AgentTokens.AsNoTracking().SingleAsync(t => t.Id == issued.TokenId);
            Assert.IsNull(token.LastExpiryNoticeDaysLeft);
        }

        await job.NotifyDueTokensAsync(CancellationToken.None);
        Assert.IsFalse(presenter.Notices.Any(n => n.Recipient.UserId == owner));
    }

    private sealed class CapturingPresenter : IKeywardAlertPresenter
    {
        public List<(KeywardAlertRecipient Recipient, IReadOnlyList<KeywardAgentTokenExpiryLine> Lines)> Notices { get; } = [];

        public bool OwnsRecipientSelection => false;

        public Task<int> NotifyTokenAlertsAsync(Guid tenantId, bool monitoring, IReadOnlyList<KeywardAlertRecipient> recipients, IReadOnlyList<KeywardTokenAlertLine> lines, CancellationToken ct = default) => Task.FromResult(0);

        public Task<int> NotifyTokenExpiryAsync(Guid tenantId, IReadOnlyList<KeywardAlertRecipient> recipients, IReadOnlyList<KeywardTokenExpiryLine> lines, CancellationToken ct = default) => Task.FromResult(0);

        public Task<int> NotifySecretExpiryAsync(Guid tenantId, IReadOnlyList<KeywardAlertRecipient> recipients, IReadOnlyList<KeywardSecretExpiryLine> lines, CancellationToken ct = default) => Task.FromResult(0);

        public Task<int> NotifyAgentTokenExpiryAsync(Guid tenantId, KeywardAlertRecipient recipient, IReadOnlyList<KeywardAgentTokenExpiryLine> lines, CancellationToken ct = default)
        {
            Notices.Add((recipient, lines));
            return Task.FromResult(1);
        }
    }
}
