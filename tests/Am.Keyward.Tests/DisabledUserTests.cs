using System.Security.Cryptography;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Infrastructure;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Am.Keyward.Tests;

/// <summary>
/// A user the host disables (or stops granting anything) is disabled in Keyward too: they count as a member of
/// no tenant — system admins included — until the host enables them again or grants them something at sign-in.
/// </summary>
[TestClass]
public class DisabledUserTests
{
    private static readonly string ConnectionString = TestConfig.ConnectionString;

    [TestMethod, TestCategory("Integration")]
    public async Task Disable_and_enable_follow_the_host()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var tenantId = Guid.NewGuid();
        var externalId = $"host-user-{Guid.NewGuid():N}";

        var bound = await BindAsync(provider, externalId, tenantId, KeywardIdentityBinding.Member);
        Assert.IsTrue(await IsMemberAsync(provider, bound.UserId, tenantId));
        Assert.IsFalse(await IsDisabledAsync(provider, bound.UserId));

        // The host's admin action, without the user signing in.
        using (var scope = provider.CreateScope())
        {
            Assert.IsTrue(await scope.ServiceProvider.GetRequiredService<IKeywardIdentityBinder>().DisableAsync(externalId));
        }

        Assert.IsTrue(await IsDisabledAsync(provider, bound.UserId));
        Assert.IsFalse(await IsMemberAsync(provider, bound.UserId, tenantId), "A disabled user is a member of no tenant.");

        using (var scope = provider.CreateScope())
        {
            Assert.IsTrue(await scope.ServiceProvider.GetRequiredService<IKeywardIdentityBinder>().EnableAsync(externalId));
        }

        Assert.IsFalse(await IsDisabledAsync(provider, bound.UserId));
        Assert.IsTrue(await IsMemberAsync(provider, bound.UserId, tenantId));
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Sign_in_binding_disables_on_nothing_and_enables_on_something()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var tenantId = Guid.NewGuid();
        var externalId = $"host-admin-{Guid.NewGuid():N}";

        var bound = await BindAsync(provider, externalId, tenantId, KeywardIdentityBinding.Administrator);
        Assert.IsTrue(await IsMemberAsync(provider, bound.UserId, tenantId));

        // The host now grants nothing: disabled — even the system-admin flag does not make them a member.
        using (var scope = provider.CreateScope())
        {
            var binder = scope.ServiceProvider.GetRequiredService<IKeywardIdentityBinder>();
            Assert.IsTrue(await binder.DisableAsync(externalId));
        }
        Assert.IsFalse(await IsMemberAsync(provider, bound.UserId, tenantId));

        // Granted something again at the next sign-in: enabled.
        await BindAsync(provider, externalId, tenantId, KeywardIdentityBinding.Administrator);
        Assert.IsFalse(await IsDisabledAsync(provider, bound.UserId));
        Assert.IsTrue(await IsMemberAsync(provider, bound.UserId, tenantId));

        // Binding with nothing disables and removes the membership.
        await BindAsync(provider, externalId, tenantId, KeywardIdentityBinding.None);
        Assert.IsTrue(await IsDisabledAsync(provider, bound.UserId));
        Assert.IsFalse(await IsMemberAsync(provider, bound.UserId, tenantId));
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Unknown_identity_reports_nothing_to_disable()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        using var scope = provider.CreateScope();
        var binder = scope.ServiceProvider.GetRequiredService<IKeywardIdentityBinder>();
        Assert.IsFalse(await binder.DisableAsync($"never-bound-{Guid.NewGuid():N}"));
        Assert.IsFalse(await binder.EnableAsync($"never-bound-{Guid.NewGuid():N}"));
    }

    private static async Task<KeywardBoundUser> BindAsync(ServiceProvider provider, string externalId, Guid tenantId, KeywardIdentityBinding binding)
    {
        using var scope = provider.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<IKeywardIdentityBinder>()
            .BindAsync(externalId, externalId, tenantId, binding);
    }

    private static async Task<bool> IsMemberAsync(ServiceProvider provider, Guid userId, Guid tenantId)
    {
        using var scope = provider.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<ITenantMembership>().IsMemberAsync(userId, tenantId);
    }

    private static async Task<bool> IsDisabledAsync(ServiceProvider provider, Guid userId)
    {
        using var scope = provider.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<KeywardDbContext>().Users
            .Where(u => u.Id == userId).Select(u => u.DisabledAt != null).SingleAsync();
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
