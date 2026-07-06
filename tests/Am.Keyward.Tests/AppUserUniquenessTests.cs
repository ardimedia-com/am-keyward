using System.Security.Cryptography;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Domain.Identity;
using Am.Keyward.Infrastructure;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Am.Keyward.Tests;

/// <summary>
/// A local (standalone-Identity) user must be unique by external id, so two concurrent just-in-time
/// creations for the same sign-in cannot fork into duplicate AppUser rows. External users stay unique per
/// (Issuer, ExternalId), so the same external id under a different issuer is still allowed. Runs against a
/// real SQL Server; skips when none is reachable.
/// </summary>
[TestClass]
public class AppUserUniquenessTests
{
    private static readonly string ConnectionString = TestConfig.ConnectionString;

    [TestMethod, TestCategory("Integration")]
    public async Task Local_user_external_id_is_unique_but_the_same_id_is_allowed_across_issuers()
    {
        await using var provider = BuildProvider();
        using (var probe = provider.CreateScope())
        {
            if (!await probe.ServiceProvider.GetRequiredService<KeywardDbContext>().Database.CanConnectAsync())
            {
                Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
                return;
            }
        }

        var externalId = Guid.NewGuid().ToString("D");
        var now = DateTimeOffset.UtcNow;

        await AddUserAsync(provider, new AppUser(Guid.NewGuid(), null, externalId, "Local A", isSystemAdmin: false, now));

        // A second local user (Issuer null) with the same external id is rejected by the filtered unique index.
        await Assert.ThrowsExactlyAsync<DbUpdateException>(() =>
            AddUserAsync(provider, new AppUser(Guid.NewGuid(), null, externalId, "Local B", isSystemAdmin: false, now)));

        // The same external id under a different issuer is a different (external) user and is allowed.
        await AddUserAsync(provider, new AppUser(Guid.NewGuid(), "https://idp.example", externalId, "External C", isSystemAdmin: false, now));
    }

    private static ServiceProvider BuildProvider()
    {
        var services = new ServiceCollection();
        services.AddKeyward(ConnectionString, RandomNumberGenerator.GetBytes(32), "test-kek:v1");
        return services.BuildServiceProvider();
    }

    private static async Task AddUserAsync(ServiceProvider provider, AppUser user)
    {
        using var scope = provider.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
        db.Users.Add(user);
        await db.SaveChangesAsync();
    }
}
