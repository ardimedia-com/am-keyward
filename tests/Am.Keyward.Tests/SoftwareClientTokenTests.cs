using System.Security.Cryptography;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Identity;
using Am.Keyward.Core.Domain.Software;
using Am.Keyward.Core.Domain.ValueObjects;
using Am.Keyward.Infrastructure;
using Am.Keyward.Infrastructure.Auth;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Am.Keyward.Tests;

[TestClass]
public class SoftwareClientTokenGeneratorTests
{
    [TestMethod, TestCategory("Auth")]
    public void Generate_produces_a_parseable_token_whose_hash_verifies()
    {
        var generated = SoftwareClientTokenGenerator.Generate();

        StringAssert.StartsWith(generated.Token, "amkw_");
        Assert.IsTrue(SoftwareClientTokenGenerator.TryParsePrefix(generated.Token, out var prefix));
        Assert.AreEqual(generated.Prefix, prefix);
        Assert.AreEqual(generated.Hash, SoftwareClientTokenGenerator.Hash(generated.Token));
    }

    [TestMethod, TestCategory("Auth")]
    public void Generate_is_unique_each_time()
    {
        Assert.AreNotEqual(SoftwareClientTokenGenerator.Generate().Token, SoftwareClientTokenGenerator.Generate().Token);
    }

    [TestMethod, TestCategory("Auth")]
    public void Generated_tokens_always_parse_across_many_samples()
    {
        // Guards against a separator clashing with the segment alphabet (Base64Url's '_' broke this).
        for (var i = 0; i < 250; i++)
        {
            var generated = SoftwareClientTokenGenerator.Generate();
            Assert.IsTrue(SoftwareClientTokenGenerator.TryParsePrefix(generated.Token, out var prefix),
                $"Token did not parse: {generated.Token}");
            Assert.AreEqual(generated.Prefix, prefix);
        }
    }

    [TestMethod, TestCategory("Auth")]
    public void TryParsePrefix_rejects_non_keyward_tokens()
    {
        Assert.IsFalse(SoftwareClientTokenGenerator.TryParsePrefix("not-a-token", out _));
        Assert.IsFalse(SoftwareClientTokenGenerator.TryParsePrefix("bearer_x_y", out _));
        Assert.IsFalse(SoftwareClientTokenGenerator.TryParsePrefix("", out _));
    }
}

/// <summary>
/// End-to-end software-client token flow against a real SQL Server: issue → authenticate → read; with
/// expiry, revocation, tampering and per-environment isolation. Skips (inconclusive) when no DB is reachable.
/// </summary>
[TestClass]
public class SoftwareClientTokenTests
{
    private const string ConnectionString = "Server=localhost;Database=amkeyward;Integrated Security=True;Encrypt=False";
    private const string Key = "ConnectionStrings:Main";

    [TestMethod, TestCategory("Integration")]
    public async Task Issue_authenticate_and_read_scopes_to_the_tokens_environment()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var tenantId = Guid.NewGuid();
        var projectId = Guid.NewGuid();
        await SeedProjectWithTwoEnvironmentsAsync(provider, tenantId, projectId, prodValue: "prod-secret", devValue: "dev-secret");

        var prodToken = await IssueAsync(provider, tenantId, projectId, "Production", expiresAt: null);
        var devToken = await IssueAsync(provider, tenantId, projectId, "Development", expiresAt: null);

        // The Production token authenticates to the Production environment and reads the Production value.
        var prodValue = await AuthenticateAndReadAsync(provider, prodToken.Token, Key);
        Assert.AreEqual("prod-secret", prodValue);

        // The Development token reads the Development value for the SAME key — env isolation by token.
        var devValue = await AuthenticateAndReadAsync(provider, devToken.Token, Key);
        Assert.AreEqual("dev-secret", devValue);
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Expired_revoked_and_tampered_tokens_are_rejected()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var tenantId = Guid.NewGuid();
        var projectId = Guid.NewGuid();
        await SeedProjectWithTwoEnvironmentsAsync(provider, tenantId, projectId, prodValue: "prod-secret", devValue: "dev-secret");

        // Expired.
        var expired = await IssueAsync(provider, tenantId, projectId, "Production", expiresAt: DateTimeOffset.UtcNow.AddMinutes(-1));
        Assert.IsNull(await AuthenticateAsync(provider, expired.Token));

        // Revoked.
        var revoked = await IssueAsync(provider, tenantId, projectId, "Production", expiresAt: null);
        using (var scope = ScopeFor(provider, tenantId))
        {
            await scope.ServiceProvider.GetRequiredService<ISoftwareClientTokenService>()
                .RevokeAsync(tenantId, revoked.TokenId, null);
        }
        Assert.IsNull(await AuthenticateAsync(provider, revoked.Token));

        // Tampered (valid prefix, wrong secret) and pure garbage.
        var valid = await IssueAsync(provider, tenantId, projectId, "Production", expiresAt: null);
        Assert.IsNull(await AuthenticateAsync(provider, valid.Token + "x"));
        Assert.IsNull(await AuthenticateAsync(provider, "amkw_deadbeef_not-the-secret"));
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Rotate_invalidates_the_old_token_and_issues_a_working_one()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var tenantId = Guid.NewGuid();
        var projectId = Guid.NewGuid();
        await SeedProjectWithTwoEnvironmentsAsync(provider, tenantId, projectId, prodValue: "prod-secret", devValue: "dev-secret");

        var original = await IssueAsync(provider, tenantId, projectId, "Production", expiresAt: null);
        IssuedSoftwareClientToken rotated;
        using (var scope = ScopeFor(provider, tenantId))
        {
            rotated = await scope.ServiceProvider.GetRequiredService<ISoftwareClientTokenService>()
                .RotateAsync(tenantId, original.TokenId, null, null);
        }

        Assert.IsNull(await AuthenticateAsync(provider, original.Token), "Old secret must stop working after rotation.");
        Assert.AreEqual("prod-secret", await AuthenticateAndReadAsync(provider, rotated.Token, Key));
    }

    // --- helpers ---

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

    private static IServiceScope ScopeFor(ServiceProvider provider, Guid tenantId)
    {
        var scope = provider.CreateScope();
        scope.ServiceProvider.GetRequiredService<ITenantScopeSetter>().SetTenant(tenantId);
        return scope;
    }

    private static async Task SeedProjectWithTwoEnvironmentsAsync(
        ServiceProvider provider, Guid tenantId, Guid projectId, string prodValue, string devValue)
    {
        using var scope = ScopeFor(provider, tenantId);
        var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
        db.Tenants.Add(new Tenant(tenantId, "system", isSystemTenant: true, DateTimeOffset.UtcNow));
        var project = new Project(projectId, tenantId, OwnerType.Tenant, tenantId, "tokens", DateTimeOffset.UtcNow);
        project.AddEnvironment(Guid.NewGuid(), EnvironmentName.Production, DateTimeOffset.UtcNow);
        project.AddEnvironment(Guid.NewGuid(), EnvironmentName.Development, DateTimeOffset.UtcNow);
        db.Projects.Add(project);
        await db.SaveChangesAsync();

        var secrets = scope.ServiceProvider.GetRequiredService<ISoftwareSecretService>();
        await secrets.StoreAsync(new StoreSoftwareSecretCommand(tenantId, projectId, "Production", Key, prodValue, null));
        await secrets.StoreAsync(new StoreSoftwareSecretCommand(tenantId, projectId, "Development", Key, devValue, null));
    }

    private static async Task<IssuedSoftwareClientToken> IssueAsync(
        ServiceProvider provider, Guid tenantId, Guid projectId, string environment, DateTimeOffset? expiresAt)
    {
        using var scope = ScopeFor(provider, tenantId);
        return await scope.ServiceProvider.GetRequiredService<ISoftwareClientTokenService>()
            .IssueAsync(new IssueSoftwareClientTokenCommand(tenantId, projectId, environment, $"{environment} token", expiresAt, null));
    }

    private static async Task<SoftwareClientPrincipal?> AuthenticateAsync(ServiceProvider provider, string token)
    {
        // Authentication runs without a tenant scope (the token table is installation-global).
        using var scope = provider.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<ISoftwareClientAuthenticator>().AuthenticateAsync(token);
    }

    private static async Task<string?> AuthenticateAndReadAsync(ServiceProvider provider, string token, string key)
    {
        var principal = await AuthenticateAsync(provider, token);
        Assert.IsNotNull(principal);

        // The host would set the scope from the token; do the same here, then read via the client reader.
        using var scope = ScopeFor(provider, principal.TenantId);
        return await scope.ServiceProvider.GetRequiredService<ISoftwareSecretReader>()
            .ReadAsync(principal.TenantId, principal.ProjectId, principal.EnvironmentId, key, null);
    }
}
