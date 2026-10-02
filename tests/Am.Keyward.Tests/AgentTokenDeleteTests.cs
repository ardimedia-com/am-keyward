using System.Security.Cryptography;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Agent;
using Am.Keyward.Infrastructure;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Am.Keyward.Tests;

/// <summary>
/// A token that no longer works can be deleted from its owner's list (2026-10-02); a working one has to be revoked
/// first, and nobody else can delete it.
/// </summary>
[TestClass]
public class AgentTokenDeleteTests
{
    [TestMethod, TestCategory("Integration")]
    public async Task Only_the_owner_deletes_and_only_a_token_that_no_longer_works()
    {
        var services = new ServiceCollection();
        services.AddKeyward(TestConfig.ConnectionString, RandomNumberGenerator.GetBytes(32), "test-kek:v1");
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

        using var scope = AgentApiTests.ScopeFor(provider, tenantId, owner);
        var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
        var vault = await vaults.CreateTenantVaultAsync(new CreateTenantVaultCommand(owner, tenantId, "KI-Tresor"));
        await vaults.SetAgentAccessAsync(owner, vault, allowed: true);
        var tokens = scope.ServiceProvider.GetRequiredService<IAgentTokenService>();
        var issued = await tokens.IssueAsync(new IssueAgentTokenCommand(owner, tenantId, "WUHARRY", AgentScopes.VaultList, [vault]));

        // A working token is revoked, not deleted; nobody acts as someone else.
        await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => tokens.DeleteAsync(owner, tenantId, issued.TokenId));
        await Assert.ThrowsExactlyAsync<UnauthorizedAccessException>(() => tokens.DeleteAsync(Guid.NewGuid(), tenantId, issued.TokenId));

        await tokens.RevokeAsync(owner, tenantId, issued.TokenId);
        await tokens.DeleteAsync(owner, tenantId, issued.TokenId);

        Assert.IsFalse((await tokens.ListAsync(owner, tenantId)).Any(t => t.Id == issued.TokenId));
        var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
        Assert.IsFalse(await db.AgentTokenVaultAllowances.AnyAsync(a => a.TokenId == issued.TokenId));
        Assert.AreEqual(1, await db.AuditEntries.AsNoTracking()
            .CountAsync(a => a.TenantId == tenantId && a.ResourceId == issued.TokenId && a.Action == AuditAction.Delete));
    }
}
