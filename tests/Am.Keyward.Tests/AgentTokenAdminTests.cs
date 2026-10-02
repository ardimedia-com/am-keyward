using System.Net;
using System.Security.Cryptography;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Agent;
using Am.Keyward.Core.Domain.Identity;
using Am.Keyward.Infrastructure;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Am.Keyward.Tests;

/// <summary>
/// Decision T11 A (2026-10-02): tenant administrators see every AI agent token of the organisation with its owner and
/// can revoke one; nobody else can, and nobody can change or issue a token for someone else.
/// </summary>
[TestClass]
public class AgentTokenAdminTests
{
    [TestMethod, TestCategory("Integration")]
    public async Task Administrators_see_and_revoke_every_token_others_see_only_their_own()
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
        var admin = Guid.NewGuid();
        var member = Guid.NewGuid();
        using (var seed = provider.CreateScope())
        {
            seed.ServiceProvider.GetRequiredService<ITenantScopeSetter>().SetTenant(tenantId);
            var db = seed.ServiceProvider.GetRequiredService<KeywardDbContext>();
            db.Tenants.Add(new Tenant(tenantId, "agent-admin-test", isSystemTenant: false, DateTimeOffset.UtcNow));
            db.Users.Add(new AppUser(admin, issuer: null, externalId: $"user-{admin:N}", displayName: "Admin", isSystemAdmin: false, DateTimeOffset.UtcNow));
            db.Users.Add(new AppUser(member, issuer: null, externalId: $"user-{member:N}", displayName: "Member", isSystemAdmin: false, DateTimeOffset.UtcNow));
            db.TenantMemberships.Add(new TenantMembership(Guid.NewGuid(), tenantId, admin, TenantRole.TenantAdmin, DateTimeOffset.UtcNow));
            db.TenantMemberships.Add(new TenantMembership(Guid.NewGuid(), tenantId, member, TenantRole.Member, DateTimeOffset.UtcNow));
            await db.SaveChangesAsync();
        }

        IssuedAgentToken issued;
        using (var scope = AgentApiTests.ScopeFor(provider, tenantId, member))
        {
            var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
            var vault = await vaults.CreateTenantVaultAsync(new CreateTenantVaultCommand(member, tenantId, "KI-Tresor"));
            await vaults.SetAgentAccessAsync(member, vault, allowed: true);
            var tokens = scope.ServiceProvider.GetRequiredService<IAgentTokenService>();
            issued = await tokens.IssueAsync(new IssueAgentTokenCommand(member, tenantId, "LAPTOP-MEMBER", AgentScopes.VaultList, [vault]));

            // A member is no administrator: no overview, no revoking someone else's token.
            Assert.IsFalse(await tokens.CanAdministerAsync(member, tenantId));
            await Assert.ThrowsExactlyAsync<UnauthorizedAccessException>(() => tokens.ListForTenantAsync(member, tenantId));
            await Assert.ThrowsExactlyAsync<UnauthorizedAccessException>(() => tokens.RevokeAsAdminAsync(member, tenantId, issued.TokenId));
        }

        using (var scope = AgentApiTests.ScopeFor(provider, tenantId, admin))
        {
            var tokens = scope.ServiceProvider.GetRequiredService<IAgentTokenService>();
            Assert.IsTrue(await tokens.CanAdministerAsync(admin, tenantId));
            var entry = (await tokens.ListForTenantAsync(admin, tenantId)).Single(e => e.Token.Id == issued.TokenId);
            Assert.AreEqual("Member", entry.OwnerName);
            Assert.AreEqual(member, entry.OwnerUserId);

            // The overview is not the owner's own list, and it changes nothing about who may edit the token.
            Assert.IsEmpty(await tokens.ListAsync(admin, tenantId));
            await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => tokens.UpdateAsync(new UpdateAgentTokenCommand(
                admin, tenantId, issued.TokenId, "taken over", AgentScopes.VaultList, [])));

            await tokens.RevokeAsAdminAsync(admin, tenantId, issued.TokenId);
            var audit = await scope.ServiceProvider.GetRequiredService<KeywardDbContext>().AuditEntries.AsNoTracking()
                .CountAsync(a => a.TenantId == tenantId && a.ResourceId == issued.TokenId && a.Action == AuditAction.Revoke);
            Assert.AreEqual(1, audit);
        }

        using (var scope = provider.CreateScope())
        {
            Assert.IsNull(await scope.ServiceProvider.GetRequiredService<IAgentAuthenticator>().AuthenticateAsync(issued.Token, IPAddress.Loopback));
        }
    }
}
