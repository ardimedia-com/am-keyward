using System.Net;
using System.Security.Cryptography;
using Am.Keyward.Api;
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
/// Agent tokens: issuance rules, authentication, and the adversarial gate for the new principal — a token may
/// reach exactly the allowlisted, agent-enabled vaults of its own tenant on which its user still holds a grant,
/// and stops working the moment any of that changes.
/// </summary>
[TestClass]
public class AgentTokenTests
{
    private static readonly string ConnectionString = TestConfig.ConnectionString;

    [TestMethod, TestCategory("Integration")]
    public async Task Issuance_rules()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var tenantId = Guid.NewGuid();
        var owner = Guid.NewGuid();
        var member = Guid.NewGuid();
        await SeedTenantAsync(provider, tenantId, owner, member);

        using var scope = ScopeFor(provider, tenantId, owner);
        var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
        var tokens = scope.ServiceProvider.GetRequiredService<IAgentTokenService>();

        var personal = await vaults.CreatePersonalVaultAsync(new CreatePersonalVaultCommand(owner, "Mine"));
        var closed = await vaults.CreateTenantVaultAsync(new CreateTenantVaultCommand(owner, tenantId, "Closed"));
        var open = await vaults.CreateTenantVaultAsync(new CreateTenantVaultCommand(owner, tenantId, "Integrations"));
        await vaults.SetAgentAccessAsync(owner, open, allowed: true);

        // A personal vault can never be opened, nor allowlisted.
        await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => vaults.SetAgentAccessAsync(owner, personal, allowed: true));
        await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => tokens.IssueAsync(Issue(owner, tenantId, personal)));

        // A tenant vault that does not allow agents cannot be allowlisted.
        await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => tokens.IssueAsync(Issue(owner, tenantId, closed)));

        // Scopes, lifetime and networks are validated.
        await Assert.ThrowsExactlyAsync<ArgumentException>(() => tokens.IssueAsync(Issue(owner, tenantId, open) with { Scopes = AgentScopes.None }));
        await Assert.ThrowsExactlyAsync<ArgumentException>(() => tokens.IssueAsync(Issue(owner, tenantId, open) with { ExpiresAt = DateTimeOffset.UtcNow.AddDays(400) }));
        await Assert.ThrowsExactlyAsync<ArgumentException>(() => tokens.IssueAsync(Issue(owner, tenantId, open) with { AllowedNetworks = "not-a-network" }));

        // A token can only be issued for oneself.
        await Assert.ThrowsExactlyAsync<UnauthorizedAccessException>(() => tokens.IssueAsync(Issue(member, tenantId, open)));

        var issued = await tokens.IssueAsync(Issue(owner, tenantId, open));
        Assert.StartsWith("amkwa_", issued.Token);
        var listed = (await tokens.ListAsync(owner, tenantId)).Single(t => t.Id == issued.TokenId);
        CollectionAssert.AreEqual(new[] { open }, listed.VaultIds.ToArray());
        Assert.IsTrue(listed.IsActive);

        // A member without a grant on the vault cannot allowlist it.
        using var memberScope = ScopeFor(provider, tenantId, member);
        await Assert.ThrowsExactlyAsync<UnauthorizedAccessException>(() =>
            memberScope.ServiceProvider.GetRequiredService<IAgentTokenService>().IssueAsync(Issue(member, tenantId, open)));
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Access_is_decided_per_request_and_follows_every_change()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var tenantId = Guid.NewGuid();
        var owner = Guid.NewGuid();
        var member = Guid.NewGuid();
        await SeedTenantAsync(provider, tenantId, owner, member);

        Guid allowlisted, other, itemInAllowlisted, itemInOther;
        using (var scope = ScopeFor(provider, tenantId, owner))
        {
            var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
            allowlisted = await vaults.CreateTenantVaultAsync(new CreateTenantVaultCommand(owner, tenantId, "Integrations"));
            other = await vaults.CreateTenantVaultAsync(new CreateTenantVaultCommand(owner, tenantId, "Other"));
            await vaults.SetAgentAccessAsync(owner, allowlisted, allowed: true);
            await vaults.SetAgentAccessAsync(owner, other, allowed: true);
            await vaults.ShareWithUserAsync(new ShareVaultWithUserCommand(owner, tenantId, allowlisted, member, Permission.Write));
            await vaults.ShareWithUserAsync(new ShareVaultWithUserCommand(owner, tenantId, other, member, Permission.Write));
            itemInAllowlisted = await vaults.AddItemAsync(new AddVaultItemCommand(owner, allowlisted, null, ItemType.Generic, "CH-Post", "secret"));
            itemInOther = await vaults.AddItemAsync(new AddVaultItemCommand(owner, other, null, ItemType.Generic, "DHL", "secret"));
        }

        // The member issues a list+write token for ONE vault, although they hold grants on both.
        IssuedAgentToken issued;
        using (var scope = ScopeFor(provider, tenantId, member))
        {
            issued = await scope.ServiceProvider.GetRequiredService<IAgentTokenService>().IssueAsync(
                Issue(member, tenantId, allowlisted) with { Scopes = AgentScopes.VaultList | AgentScopes.VaultWrite });
        }

        var principal = await AuthenticateAsync(provider, issued.Token);
        Assert.IsNotNull(principal);
        Assert.AreEqual(member, principal.UserId);
        Assert.AreEqual(tenantId, principal.TenantId);

        Task<bool> Vault(Guid vaultId, AgentScopes scope = AgentScopes.VaultList, Permission permission = Permission.Read) =>
            AllowedAsync(provider, tenantId, a => a.IsVaultAllowedAsync(issued.TokenId, vaultId, scope, permission));
        Task<bool> Item(Guid itemId) =>
            AllowedAsync(provider, tenantId, a => a.IsItemAllowedAsync(issued.TokenId, itemId, AgentScopes.VaultList, Permission.Read));

        Assert.IsTrue(await Vault(allowlisted));
        Assert.IsTrue(await Vault(allowlisted, AgentScopes.VaultWrite, Permission.Write));
        Assert.IsTrue(await Item(itemInAllowlisted));

        // Not on the allowlist — even with a grant and the flag on — and item routes go through the item's vault.
        Assert.IsFalse(await Vault(other));
        Assert.IsFalse(await Item(itemInOther));

        // A scope the token was not given, a permission the user does not hold, an unknown vault or item.
        Assert.IsFalse(await Vault(allowlisted, AgentScopes.VaultReveal));
        Assert.IsFalse(await Vault(allowlisted, AgentScopes.VaultWrite, Permission.Manage));
        Assert.IsFalse(await Vault(Guid.NewGuid()));
        Assert.IsFalse(await Item(Guid.NewGuid()));

        // The owner closes the vault to agents: the token loses it on the next request; reopening restores it.
        await AsUserAsync(provider, tenantId, owner, v => v.SetAgentAccessAsync(owner, allowlisted, allowed: false));
        Assert.IsFalse(await Vault(allowlisted));
        await AsUserAsync(provider, tenantId, owner, v => v.SetAgentAccessAsync(owner, allowlisted, allowed: true));
        Assert.IsTrue(await Vault(allowlisted));

        // The member loses the grant: so does the token.
        await AsUserAsync(provider, tenantId, owner, v => v.RevokeShareAsync(owner, tenantId, allowlisted, PrincipalType.User, member));
        Assert.IsFalse(await Vault(allowlisted));
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Another_tenants_vault_stays_unreachable_even_when_allowlisted()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var tenantA = Guid.NewGuid();
        var userA = Guid.NewGuid();
        var tenantB = Guid.NewGuid();
        var userB = Guid.NewGuid();
        await SeedTenantAsync(provider, tenantA, userA);
        await SeedTenantAsync(provider, tenantB, userB);

        var vaultA = await CreateOpenVaultAsync(provider, tenantA, userA, "A");
        var vaultB = await CreateOpenVaultAsync(provider, tenantB, userB, "B");

        IssuedAgentToken issued;
        using (var scope = ScopeFor(provider, tenantA, userA))
        {
            issued = await scope.ServiceProvider.GetRequiredService<IAgentTokenService>().IssueAsync(Issue(userA, tenantA, vaultA));

            // Issuance refuses the other tenant's vault outright.
            await Assert.ThrowsExactlyAsync<InvalidOperationException>(() =>
                scope.ServiceProvider.GetRequiredService<IAgentTokenService>().IssueAsync(Issue(userA, tenantA, vaultB)));
        }

        // Even a forged allowlist row (straight into the database) does not open tenant B's vault.
        using (var scope = provider.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
            db.AgentTokenVaultAllowances.Add(new AgentTokenVaultAllowance(issued.TokenId, vaultB));
            await db.SaveChangesAsync();
        }

        Assert.IsFalse(await AllowedAsync(provider, tenantA, a => a.IsVaultAllowedAsync(issued.TokenId, vaultB, AgentScopes.VaultList, Permission.Read)));
        Assert.IsFalse(await AllowedAsync(provider, tenantB, a => a.IsVaultAllowedAsync(issued.TokenId, vaultB, AgentScopes.VaultList, Permission.Read)),
            "A token never acts outside its own tenant, whatever scope the request runs in.");
        Assert.IsTrue(await AllowedAsync(provider, tenantA, a => a.IsVaultAllowedAsync(issued.TokenId, vaultA, AgentScopes.VaultList, Permission.Read)));
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Revoked_rotated_disabled_and_foreign_network_tokens_are_refused()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var tenantId = Guid.NewGuid();
        var owner = Guid.NewGuid();
        var externalId = $"agent-owner-{Guid.NewGuid():N}";
        await SeedTenantAsync(provider, tenantId, (owner, externalId));
        var vault = await CreateOpenVaultAsync(provider, tenantId, owner, "Integrations");

        using var scope = ScopeFor(provider, tenantId, owner);
        var tokens = scope.ServiceProvider.GetRequiredService<IAgentTokenService>();

        // Tampered, wrong kind, unknown.
        var genuine = await tokens.IssueAsync(Issue(owner, tenantId, vault));
        Assert.IsNotNull(await AuthenticateAsync(provider, genuine.Token));
        Assert.IsNull(await AuthenticateAsync(provider, genuine.Token[..^1] + (genuine.Token[^1] == '0' ? '1' : '0')));
        Assert.IsNull(await AuthenticateAsync(provider, genuine.Token.Replace("amkwa_", "amkw_")));
        Assert.IsNull(await AuthenticateAsync(provider, "amkwa_000000000000_" + new string('0', 64)));

        // Rotation: the old secret stops, the new one works.
        var rotated = await tokens.RotateAsync(owner, tenantId, genuine.TokenId);
        Assert.IsNull(await AuthenticateAsync(provider, genuine.Token));
        Assert.IsNotNull(await AuthenticateAsync(provider, rotated.Token));

        // Revocation.
        await tokens.RevokeAsync(owner, tenantId, genuine.TokenId);
        Assert.IsNull(await AuthenticateAsync(provider, rotated.Token));

        // Networks: outside the range refused, inside (also as IPv4-mapped IPv6) accepted, unknown caller refused.
        var lan = await tokens.IssueAsync(Issue(owner, tenantId, vault) with { AllowedNetworks = "10.0.0.0/8, 192.168.10.0/24" });
        Assert.IsNull(await AuthenticateAsync(provider, lan.Token, IPAddress.Parse("203.0.113.7")));
        Assert.IsNotNull(await AuthenticateAsync(provider, lan.Token, IPAddress.Parse("10.1.2.3")));
        Assert.IsNotNull(await AuthenticateAsync(provider, lan.Token, IPAddress.Parse("::ffff:192.168.10.20")));
        Assert.IsNull(await AuthenticateAsync(provider, lan.Token, null));

        // Disabling the user refuses the token at once and revokes it for good.
        var beforeDisable = await tokens.IssueAsync(Issue(owner, tenantId, vault));
        using (var bindScope = provider.CreateScope())
        {
            Assert.IsTrue(await bindScope.ServiceProvider.GetRequiredService<IKeywardIdentityBinder>().DisableAsync(externalId));
        }

        Assert.IsNull(await AuthenticateAsync(provider, beforeDisable.Token));
        using (var bindScope = provider.CreateScope())
        {
            await bindScope.ServiceProvider.GetRequiredService<IKeywardIdentityBinder>().EnableAsync(externalId);
        }

        Assert.IsNull(await AuthenticateAsync(provider, beforeDisable.Token), "Enabling the user again must not bring a revoked token back.");
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Handler_runs_the_request_as_the_tokens_user_and_audits_it_as_the_agent()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddKeyward(ConnectionString, RandomNumberGenerator.GetBytes(32), "test-kek:v1");
        services.AddKeywardAgentApi();
        await using var provider = services.BuildServiceProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var tenantId = Guid.NewGuid();
        var owner = Guid.NewGuid();
        await SeedTenantAsync(provider, tenantId, owner);
        var vault = await CreateOpenVaultAsync(provider, tenantId, owner, "Integrations");
        IssuedAgentToken issued;
        using (var scope = ScopeFor(provider, tenantId, owner))
        {
            issued = await scope.ServiceProvider.GetRequiredService<IAgentTokenService>().IssueAsync(Issue(owner, tenantId, vault));
        }

        async Task<(bool Succeeded, IServiceScope Scope)> AuthenticateHttpAsync(string authorization)
        {
            var scope = provider.CreateScope();
            var context = new Microsoft.AspNetCore.Http.DefaultHttpContext { RequestServices = scope.ServiceProvider };
            context.Request.Headers.Authorization = authorization;
            context.Connection.RemoteIpAddress = IPAddress.Parse("10.9.8.7");
            var result = await scope.ServiceProvider.GetRequiredService<Microsoft.AspNetCore.Authentication.IAuthenticationService>()
                .AuthenticateAsync(context, Am.Keyward.Api.AgentAuthenticationHandler.SchemeName);
            return (result.Succeeded, scope);
        }

        var (succeeded, requestScope) = await AuthenticateHttpAsync("Bearer " + issued.Token);
        using (requestScope)
        {
            Assert.IsTrue(succeeded);
            var sp = requestScope.ServiceProvider;
            Assert.AreEqual(tenantId, sp.GetRequiredService<ICurrentTenant>().TenantId);
            Assert.AreEqual(owner, sp.GetRequiredService<ICurrentUser>().UserId);
            Assert.AreEqual(ActorKind.Agent, sp.GetRequiredService<ICurrentActor>().Kind);
            Assert.AreEqual(issued.TokenId, sp.GetRequiredService<ICurrentActor>().TokenId);
        }

        var (failed, failedScope) = await AuthenticateHttpAsync("Bearer amkwa_000000000000_" + new string('0', 64));
        using (failedScope)
        {
            Assert.IsFalse(failed);
            Assert.IsNull(failedScope.ServiceProvider.GetRequiredService<ICurrentUser>().UserId, "A refused token must not leave a user in scope.");
        }
    }

    private static IssueAgentTokenCommand Issue(Guid userId, Guid tenantId, Guid vaultId) =>
        new(userId, tenantId, $"agent-{Guid.NewGuid():N}", AgentScopes.VaultList | AgentScopes.VaultRead, [vaultId]);

    private static async Task<Guid> CreateOpenVaultAsync(ServiceProvider provider, Guid tenantId, Guid userId, string name)
    {
        using var scope = ScopeFor(provider, tenantId, userId);
        var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
        var vaultId = await vaults.CreateTenantVaultAsync(new CreateTenantVaultCommand(userId, tenantId, name));
        await vaults.SetAgentAccessAsync(userId, vaultId, allowed: true);
        return vaultId;
    }

    private static async Task<AgentPrincipal?> AuthenticateAsync(ServiceProvider provider, string token, IPAddress? clientIp = null)
    {
        // Authentication runs without any scope (the token table is installation-global).
        using var scope = provider.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<IAgentAuthenticator>()
            .AuthenticateAsync(token, clientIp ?? IPAddress.Loopback);
    }

    // As the agent handler does: the request runs in the token's tenant scope.
    private static async Task<bool> AllowedAsync(ServiceProvider provider, Guid tenantId, Func<IAgentVaultAccess, Task<bool>> check)
    {
        using var scope = provider.CreateScope();
        scope.ServiceProvider.GetRequiredService<ITenantScopeSetter>().SetTenant(tenantId);
        return await check(scope.ServiceProvider.GetRequiredService<IAgentVaultAccess>());
    }

    private static async Task AsUserAsync(ServiceProvider provider, Guid tenantId, Guid userId, Func<IVaultService, Task> action)
    {
        using var scope = ScopeFor(provider, tenantId, userId);
        await action(scope.ServiceProvider.GetRequiredService<IVaultService>());
    }

    private static Task SeedTenantAsync(ServiceProvider provider, Guid tenantId, params Guid[] users) =>
        SeedTenantAsync(provider, tenantId, users.Select(u => (u, $"user-{u:N}")).ToArray());

    private static async Task SeedTenantAsync(ServiceProvider provider, Guid tenantId, params (Guid UserId, string ExternalId)[] users)
    {
        using var scope = provider.CreateScope();
        scope.ServiceProvider.GetRequiredService<ITenantScopeSetter>().SetTenant(tenantId);
        var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
        db.Tenants.Add(new Tenant(tenantId, "agent-test", isSystemTenant: false, DateTimeOffset.UtcNow));
        foreach (var (userId, externalId) in users)
        {
            db.Users.Add(new AppUser(userId, issuer: null, externalId: externalId, displayName: externalId, isSystemAdmin: false, DateTimeOffset.UtcNow));
            db.TenantMemberships.Add(new TenantMembership(Guid.NewGuid(), tenantId, userId, TenantRole.Member, DateTimeOffset.UtcNow));
        }

        await db.SaveChangesAsync();
    }

    private static IServiceScope ScopeFor(ServiceProvider provider, Guid tenantId, Guid userId)
    {
        var scope = provider.CreateScope();
        scope.ServiceProvider.GetRequiredService<ITenantScopeSetter>().SetTenant(tenantId);
        scope.ServiceProvider.GetRequiredService<IUserScopeSetter>().SetUser(userId);
        return scope;
    }

    private static ServiceProvider BuildProvider()
    {
        var services = new ServiceCollection();
        services.AddKeyward(ConnectionString, RandomNumberGenerator.GetBytes(32), "test-kek:v1");
        return services.BuildServiceProvider();
    }

    private static async Task<bool> CanConnectAsync(ServiceProvider provider)
    {
        using var scope = provider.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<KeywardDbContext>().Database.CanConnectAsync();
    }
}
