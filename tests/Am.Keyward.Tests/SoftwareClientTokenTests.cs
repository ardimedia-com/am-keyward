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

[TestClass]
public class TokenExpiryNoticePolicyTests
{
    [TestMethod, TestCategory("Auth")]
    public void Schedule_is_30_20_10_then_daily_from_9()
    {
        // First notice per bucket (nothing sent yet).
        foreach (var dueDay in new[] { 30, 20, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 })
        {
            Assert.IsTrue(TokenExpiryNoticePolicy.IsDue(dueDay, null), $"day {dueDay} must be due");
        }

        // Between the coarse buckets nothing fires.
        foreach (var quietDay in new[] { 31, 29, 25, 21, 19, 15, 11 })
        {
            Assert.IsFalse(TokenExpiryNoticePolicy.IsDue(quietDay, null), $"day {quietDay} must be quiet");
        }

        // Expired (or expiring within the current day math) sends nothing.
        Assert.IsFalse(TokenExpiryNoticePolicy.IsDue(0, null));
        Assert.IsFalse(TokenExpiryNoticePolicy.IsDue(-3, null));
    }

    [TestMethod, TestCategory("Auth")]
    public void Notices_are_deduplicated_and_monotonic()
    {
        // 30 announced → 30 stays quiet on the next (e.g. hourly) run, 20 fires later.
        Assert.IsFalse(TokenExpiryNoticePolicy.IsDue(30, 30));
        Assert.IsTrue(TokenExpiryNoticePolicy.IsDue(20, 30));

        // Daily phase: each new day fires once.
        Assert.IsTrue(TokenExpiryNoticePolicy.IsDue(9, 10));
        Assert.IsFalse(TokenExpiryNoticePolicy.IsDue(9, 9));
        Assert.IsTrue(TokenExpiryNoticePolicy.IsDue(8, 9));

        // A skipped window (service was down) still fires the nearest due bucket once.
        Assert.IsTrue(TokenExpiryNoticePolicy.IsDue(7, 20));
    }

    [TestMethod, TestCategory("Auth")]
    public void DaysLeft_rounds_up_so_today_counts_as_one()
    {
        var now = new DateTimeOffset(2026, 7, 7, 12, 0, 0, TimeSpan.Zero);
        Assert.AreEqual(1, TokenExpiryNoticePolicy.DaysLeft(now, now.AddHours(6)));
        Assert.AreEqual(1, TokenExpiryNoticePolicy.DaysLeft(now, now.AddDays(1)));
        Assert.AreEqual(2, TokenExpiryNoticePolicy.DaysLeft(now, now.AddDays(1).AddMinutes(1)));
        Assert.AreEqual(30, TokenExpiryNoticePolicy.DaysLeft(now, now.AddDays(30)));
    }
}

/// <summary>
/// End-to-end software-client token flow against a real SQL Server: issue → authenticate → read; with
/// expiry, revocation, tampering and per-environment isolation. Skips (inconclusive) when no DB is reachable.
/// </summary>
[TestClass]
public class SoftwareClientTokenTests
{
    private static readonly string ConnectionString = TestConfig.ConnectionString;
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

        var expiry = DateTimeOffset.UtcNow.AddDays(30);
        var original = await IssueAsync(provider, tenantId, projectId, "Production", expiresAt: expiry);
        IssuedSoftwareClientToken rotated;
        using (var scope = ScopeFor(provider, tenantId))
        {
            // Rotate without a new expiry (the UI always does this): the existing expiry must be preserved,
            // not silently cleared to "never expires".
            rotated = await scope.ServiceProvider.GetRequiredService<ISoftwareClientTokenService>()
                .RotateAsync(tenantId, original.TokenId, null, null);
        }

        Assert.IsNull(await AuthenticateAsync(provider, original.Token), "Old secret must stop working after rotation.");
        Assert.AreEqual("prod-secret", await AuthenticateAndReadAsync(provider, rotated.Token, Key));
        Assert.IsNotNull(rotated.ExpiresAt, "Rotation must keep the token's existing expiry.");
        Assert.IsTrue((rotated.ExpiresAt!.Value - expiry).Duration() < TimeSpan.FromSeconds(1),
            "Rotation must keep the token's existing expiry unchanged.");
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Issuing_a_token_writes_an_attributed_audit_entry()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var tenantId = Guid.NewGuid();
        var projectId = Guid.NewGuid();
        var actor = Guid.NewGuid();
        await SeedProjectWithTwoEnvironmentsAsync(provider, tenantId, projectId, prodValue: "p", devValue: "d");

        Guid tokenId;
        using (var scope = ScopeFor(provider, tenantId))
        {
            var issued = await scope.ServiceProvider.GetRequiredService<ISoftwareClientTokenService>()
                .IssueAsync(new IssueSoftwareClientTokenCommand(tenantId, projectId, "Production", "ci token", null, actor));
            tokenId = issued.TokenId;
        }

        using (var scope = ScopeFor(provider, tenantId))
        {
            var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
            var audited = await db.AuditEntries.AnyAsync(a =>
                a.TenantId == tenantId && a.ResourceType == "SoftwareClientToken"
                && a.ResourceId == tokenId && a.Action == AuditAction.Create);
            Assert.IsTrue(audited, "Issuing a software-client token must write an audit entry.");
        }
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

    [TestMethod, TestCategory("Integration")]
    public async Task Environments_can_be_renamed_and_deleted_with_cascade_and_guards()
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
        var devToken = await IssueAsync(provider, tenantId, projectId, "Development", expiresAt: null);

        using var scope = ScopeFor(provider, tenantId);
        var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
        var admin = Guid.NewGuid();
        db.Users.Add(new Core.Domain.Identity.AppUser(admin, issuer: null, externalId: admin.ToString(), displayName: "op", isSystemAdmin: true, DateTimeOffset.UtcNow));
        await db.SaveChangesAsync();
        scope.ServiceProvider.GetRequiredService<IUserScopeSetter>().SetUser(admin);

        var secrets = scope.ServiceProvider.GetRequiredService<ISoftwareSecretService>();
        var tokens = scope.ServiceProvider.GetRequiredService<ISoftwareClientTokenService>();

        // A non-operator may not mutate environments.
        await Assert.ThrowsExactlyAsync<UnauthorizedAccessException>(() =>
            secrets.AddEnvironmentAsync(tenantId, projectId, "Staging", actorUserId: null));

        // Rename: values and tokens follow (they bind by id).
        var dev = (await secrets.ListEnvironmentsAsync(tenantId, projectId)).Single(e => e.Name == "Development");
        await secrets.RenameEnvironmentAsync(tenantId, projectId, dev.Id, "Dev", admin);
        Assert.IsTrue((await secrets.ListEnvironmentsAsync(tenantId, projectId)).Any(e => e.Name == "Dev"));
        Assert.AreEqual("dev-secret", await AuthenticateAndReadAsync(provider, devToken.Token, Key));

        // Delete: the environment's values AND its tokens go with it; the other environment is untouched.
        await secrets.DeleteEnvironmentAsync(tenantId, projectId, dev.Id, admin);
        Assert.IsFalse((await secrets.ListEnvironmentsAsync(tenantId, projectId)).Any(e => e.Name == "Dev"));
        Assert.IsFalse((await tokens.ListAsync(tenantId, projectId)).Any(x => x.Id == devToken.TokenId));
        Assert.IsNull(await AuthenticateAsync(provider, devToken.Token));
        var detail = await secrets.GetSecretAsync(tenantId, projectId, Key);
        Assert.AreEqual("prod-secret", detail!.Environments.Single(e => e.Environment == "Production").Value);

        // The last environment is protected.
        var prod = (await secrets.ListEnvironmentsAsync(tenantId, projectId)).Single();
        await Assert.ThrowsExactlyAsync<InvalidOperationException>(() =>
            secrets.DeleteEnvironmentAsync(tenantId, projectId, prod.Id, admin));
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Rotation_renews_the_validity_window_with_the_original_lifetime()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var tenantId = Guid.NewGuid();
        var projectId = Guid.NewGuid();
        await SeedProjectWithTwoEnvironmentsAsync(provider, tenantId, projectId, prodValue: "p", devValue: "d");

        var issued = await IssueAsync(provider, tenantId, projectId, "Production", expiresAt: DateTimeOffset.UtcNow.AddDays(10));

        using var scope = ScopeFor(provider, tenantId);
        var tokens = scope.ServiceProvider.GetRequiredService<ISoftwareClientTokenService>();

        var before = (await tokens.ListAsync(tenantId, projectId)).Single(x => x.Id == issued.TokenId);
        var rotated = await tokens.RotateAsync(tenantId, issued.TokenId, null, null);
        var after = (await tokens.ListAsync(tenantId, projectId)).Single(x => x.Id == issued.TokenId);

        // The secret changed, the window restarted, and the ORIGINAL ~10-day lifetime was re-applied.
        Assert.AreNotEqual(before.TokenPrefix, after.TokenPrefix);
        Assert.IsTrue(after.CreatedAt >= before.CreatedAt);
        Assert.IsTrue(after.IsActive);
        Assert.IsNotNull(after.ExpiresAt);
        var lifetime = after.ExpiresAt!.Value - after.CreatedAt;
        Assert.IsTrue(lifetime > TimeSpan.FromDays(9.9) && lifetime < TimeSpan.FromDays(10.1),
            $"Rotated lifetime was {lifetime}.");
        Assert.AreEqual(after.ExpiresAt, rotated.ExpiresAt);
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Token_names_are_unique_per_application_but_environments_allow_several_tokens()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var tenantId = Guid.NewGuid();
        var projectId = Guid.NewGuid();
        await SeedProjectWithTwoEnvironmentsAsync(provider, tenantId, projectId, prodValue: "p", devValue: "d");

        using var scope = ScopeFor(provider, tenantId);
        var tokens = scope.ServiceProvider.GetRequiredService<ISoftwareClientTokenService>();

        // Several tokens for the SAME environment are fine (one per host, overlap during a swap) —
        // they just need distinct names.
        var first = await tokens.IssueAsync(new IssueSoftwareClientTokenCommand(tenantId, projectId, "Production", "prod-web1", null, null));
        await tokens.IssueAsync(new IssueSoftwareClientTokenCommand(tenantId, projectId, "Production", "prod-web2", null, null));

        // A duplicate name in the same application is rejected — on issue and on rename.
        await Assert.ThrowsExactlyAsync<InvalidOperationException>(() =>
            tokens.IssueAsync(new IssueSoftwareClientTokenCommand(tenantId, projectId, "Development", "prod-web1", null, null)));
        await Assert.ThrowsExactlyAsync<InvalidOperationException>(() =>
            tokens.UpdateAsync(tenantId, first.TokenId, "prod-web2", "", null));

        // Renaming a token to its own current name stays allowed (note-only edits).
        await tokens.UpdateAsync(tenantId, first.TokenId, "prod-web1", "note", null);

        // An empty name gets the "<application>-<environment>" default, numbered when already taken.
        var auto1 = await tokens.IssueAsync(new IssueSoftwareClientTokenCommand(tenantId, projectId, "Production", "", null, null));
        var auto2 = await tokens.IssueAsync(new IssueSoftwareClientTokenCommand(tenantId, projectId, "Production", "", null, null));
        var byId = (await tokens.ListAsync(tenantId, projectId)).ToDictionary(t => t.Id, t => t.Name);
        Assert.AreEqual("tokens-production", byId[auto1.TokenId]);
        Assert.AreEqual("tokens-production-2", byId[auto2.TokenId]);
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Revoked_tokens_can_be_reactivated_and_tokens_can_be_deleted()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var tenantId = Guid.NewGuid();
        var projectId = Guid.NewGuid();
        await SeedProjectWithTwoEnvironmentsAsync(provider, tenantId, projectId, prodValue: "prod-secret", devValue: "d");

        var issued = await IssueAsync(provider, tenantId, projectId, "Production", expiresAt: null);

        using var scope = ScopeFor(provider, tenantId);
        var tokens = scope.ServiceProvider.GetRequiredService<ISoftwareClientTokenService>();

        // Revoke → the secret stops working; reactivate → the SAME secret works again.
        await tokens.RevokeAsync(tenantId, issued.TokenId, null);
        Assert.IsNull(await AuthenticateAsync(provider, issued.Token));
        await tokens.ReactivateAsync(tenantId, issued.TokenId, null);
        Assert.AreEqual("prod-secret", await AuthenticateAndReadAsync(provider, issued.Token, Key));
        var reactivated = (await tokens.ListAsync(tenantId, projectId)).Single(x => x.Id == issued.TokenId);
        Assert.IsNull(reactivated.RevokedAt);
        Assert.IsTrue(reactivated.IsActive);

        // Delete → gone from the list and rejected at the door.
        await tokens.DeleteAsync(tenantId, issued.TokenId, null);
        Assert.IsFalse((await tokens.ListAsync(tenantId, projectId)).Any(x => x.Id == issued.TokenId));
        Assert.IsNull(await AuthenticateAsync(provider, issued.Token));
    }

    private static async Task<IssuedSoftwareClientToken> IssueAsync(
        ServiceProvider provider, Guid tenantId, Guid projectId, string environment, DateTimeOffset? expiresAt)
    {
        using var scope = ScopeFor(provider, tenantId);
        // Unique per call: token names are unique per application, and several tests issue multiple
        // tokens for the same environment.
        return await scope.ServiceProvider.GetRequiredService<ISoftwareClientTokenService>()
            .IssueAsync(new IssueSoftwareClientTokenCommand(tenantId, projectId, environment, $"{environment} token {Guid.NewGuid():N}", expiresAt, null));
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
