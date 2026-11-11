using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using Am.Keyward.Api;
using Am.Keyward.AspNetCore;
using Am.Keyward.Contracts;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Agent;
using Am.Keyward.Core.Domain.Identity;
using Am.Keyward.Core.Domain.Software;
using Am.Keyward.Infrastructure;
using Am.Keyward.Infrastructure.Auth;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Am.Keyward.Tests;

/// <summary>
/// Review 3, area API / authorization / software secrets: the management API is operator-only and answers 4xx instead
/// of 500, refuses cross-site requests, never touches a token of another application; junk tokens cannot lock out a
/// valid one; refused tokens are audited; reads never need the version history; a foreign tenant's token gets 403 in a
/// single-tenant host.
/// </summary>
[TestClass]
public class Review3ApiTests
{
    private const string UserHeader = "X-Test-User";

    private static string Base(Guid tenantId, Guid appId) => $"{KeywardApiDefaults.BasePath}/tenants/{tenantId}/projects/{appId}";

    [TestMethod, TestCategory("Integration")]
    public async Task Every_management_route_refuses_a_member_who_is_no_operator()
    {
        await using var app = await StartManagementAsync();
        if (app is null)
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var (tenantId, admin, member) = await SeedAsync(app.Services);
        var (appId, tokenId) = await CreateApplicationAsync(app.Services, tenantId, admin, "mgmt", "Api:Key", "plain-v1");
        var url = Base(tenantId, appId);

        var asMember = ClientFor(app, member);
        var responses = new[]
        {
            await asMember.GetAsync($"{url}/environments/Production/secrets/Api:Key"),
            await asMember.PutAsJsonAsync($"{url}/environments/Production/secrets/Api:Key", new { value = "x" }),
            await asMember.PostAsJsonAsync($"{url}/environments/Production/tokens", new { name = "sneaky" }),
            await asMember.GetAsync($"{url}/tokens"),
            await asMember.PostAsJsonAsync($"{url}/tokens/{tokenId}/rotate", new { }),
            await asMember.SendAsync(Deliberate(HttpMethod.Delete, $"{url}/tokens/{tokenId}")),
        };

        foreach (var response in responses)
        {
            Assert.AreEqual(HttpStatusCode.Forbidden, response.StatusCode, response.RequestMessage!.RequestUri!.ToString());
            Assert.DoesNotContain("plain-v1", await response.Content.ReadAsStringAsync());
        }

        // The operator is served, and a decrypted value is not cached.
        var asAdmin = ClientFor(app, admin);
        var read = await asAdmin.GetAsync($"{url}/environments/Production/secrets/Api:Key");
        Assert.AreEqual(HttpStatusCode.OK, read.StatusCode);
        Assert.AreEqual("plain-v1", (await read.Content.ReadFromJsonAsync<SecretResponse>())!.Value);
        Assert.IsTrue(read.Headers.CacheControl?.NoStore);
        Assert.AreEqual(HttpStatusCode.OK, (await asAdmin.GetAsync($"{url}/tokens")).StatusCode);

        // The token-authenticated client read path is unaffected: the token, not a role, authorizes it.
        using (var scope = app.Services.CreateScope())
        {
            scope.ServiceProvider.GetRequiredService<ITenantScopeSetter>().SetTenant(tenantId);
            var environmentId = (await scope.ServiceProvider.GetRequiredService<KeywardDbContext>().RuntimeEnvironments
                .SingleAsync(e => e.ProjectId == appId && e.Name == Core.Domain.ValueObjects.EnvironmentName.Production)).Id;
            var all = await scope.ServiceProvider.GetRequiredService<ISoftwareSecretReader>().ReadAllAsync(tenantId, appId, environmentId);
            Assert.AreEqual("plain-v1", all.Single(kv => kv.Key == "Api:Key").Value);
        }

        // An in-process host reading its own secret as a declared system caller still works.
        using (var scope = app.Services.CreateScope())
        {
            scope.ServiceProvider.GetRequiredService<ITenantScopeSetter>().SetTenant(tenantId);
            scope.ServiceProvider.GetRequiredService<IActorScopeSetter>().SetSystemActor();
            Assert.AreEqual("plain-v1", await scope.ServiceProvider.GetRequiredService<ISoftwareSecretService>()
                .ReadAsync(new ReadSoftwareSecretQuery(tenantId, appId, "Production", "Api:Key", null)));
        }
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Management_errors_answer_4xx_cross_site_requests_are_refused_and_foreign_tokens_are_not_found()
    {
        await using var app = await StartManagementAsync();
        if (app is null)
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var (tenantId, admin, _) = await SeedAsync(app.Services);
        var (appId, tokenId) = await CreateApplicationAsync(app.Services, tenantId, admin, "errors", "Api:Key", "v1");
        var (otherAppId, otherTokenId) = await CreateApplicationAsync(app.Services, tenantId, admin, "other", "Api:Key", "v1");
        var url = Base(tenantId, appId);
        var client = ClientFor(app, admin);

        Assert.AreEqual(HttpStatusCode.NotFound,
            (await client.PutAsJsonAsync($"{url}/environments/Nowhere/secrets/Api:Key", new { value = "x" })).StatusCode, "unknown environment");
        Assert.AreEqual(HttpStatusCode.BadRequest,
            (await client.PutAsJsonAsync($"{url}/environments/Production/secrets/Api:Key", new { value = (string?)null })).StatusCode, "null value");
        Assert.AreEqual(HttpStatusCode.BadRequest,
            (await client.PutAsJsonAsync($"{url}/environments/Production/secrets/not a key", new { value = "x" })).StatusCode, "invalid key");
        Assert.AreEqual(HttpStatusCode.NotFound,
            (await client.GetAsync($"{url}/environments/Production/secrets/Missing:Key")).StatusCode);
        Assert.AreEqual(HttpStatusCode.NotFound,
            (await client.PostAsJsonAsync($"{url}/environments/Nowhere/tokens", new { name = "x" })).StatusCode);
        Assert.AreEqual(HttpStatusCode.OK,
            (await client.PostAsJsonAsync($"{url}/environments/Production/tokens", new { name = "dup" })).StatusCode);
        Assert.AreEqual(HttpStatusCode.Conflict,
            (await client.PostAsJsonAsync($"{url}/environments/Production/tokens", new { name = "dup" })).StatusCode, "token name taken");

        // Cross-site request forgery: neither JSON nor the management header → refused before anything happens.
        Assert.AreEqual(HttpStatusCode.UnsupportedMediaType, (await client.DeleteAsync($"{url}/tokens/{tokenId}")).StatusCode);
        Assert.AreEqual(HttpStatusCode.UnsupportedMediaType, (await client.PostAsync($"{url}/tokens/{tokenId}/rotate", null)).StatusCode);
        var form = new FormUrlEncodedContent([new KeyValuePair<string, string>("value", "forged")]);
        Assert.AreEqual(HttpStatusCode.UnsupportedMediaType, (await client.PutAsync($"{url}/environments/Production/secrets/Api:Key", form)).StatusCode);

        // A token of ANOTHER application is not reachable through this application's route.
        Assert.AreEqual(HttpStatusCode.NotFound, (await client.SendAsync(Deliberate(HttpMethod.Post, $"{url}/tokens/{otherTokenId}/rotate"))).StatusCode);
        Assert.AreEqual(HttpStatusCode.NotFound, (await client.SendAsync(Deliberate(HttpMethod.Delete, $"{url}/tokens/{otherTokenId}"))).StatusCode);
        using (var scope = app.Services.CreateScope())
        {
            scope.ServiceProvider.GetRequiredService<ITenantScopeSetter>().SetTenant(tenantId);
            scope.ServiceProvider.GetRequiredService<IUserScopeSetter>().SetUser(admin);
            var other = (await scope.ServiceProvider.GetRequiredService<ISoftwareClientTokenService>().ListAsync(tenantId, otherAppId))
                .Single(t => t.Id == otherTokenId);
            Assert.IsNull(other.RevokedAt, "the foreign token stays untouched");
        }

        // With the header (or JSON) the same calls go through.
        var rotated = await client.SendAsync(Deliberate(HttpMethod.Post, $"{url}/tokens/{tokenId}/rotate"));
        Assert.AreEqual(HttpStatusCode.OK, rotated.StatusCode);
        Assert.AreEqual(HttpStatusCode.NoContent, (await client.SendAsync(Deliberate(HttpMethod.Delete, $"{url}/tokens/{tokenId}"))).StatusCode);
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Junk_tokens_from_one_address_never_lock_out_a_valid_agent_token()
    {
        await using var app = await AgentApiTests.StartAsync(agentOptions: o => o.FailedAuthenticationLimit = 3);
        if (app is null)
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var tenantId = Guid.NewGuid();
        var owner = Guid.NewGuid();
        await AgentApiTests.SeedTenantAsync(app.Services, tenantId, owner);
        Guid vault;
        using (var scope = AgentApiTests.ScopeFor(app.Services, tenantId, owner))
        {
            vault = await scope.ServiceProvider.GetRequiredService<IVaultService>().CreateTenantVaultAsync(new CreateTenantVaultCommand(owner, tenantId, "v"));
            await scope.ServiceProvider.GetRequiredService<IVaultService>().SetAgentAccessAsync(owner, vault, allowed: true);
        }

        var token = await AgentApiTests.IssueAsync(app.Services, tenantId, owner, vault, AgentScopes.VaultList);
        var http = app.GetTestClient();

        async Task<HttpStatusCode> PingAsync(string bearer)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, $"{KeywardAgentApi.DefaultPrefix}/ping");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
            request.Headers.Add(AgentApiTests.TestClientIpHeader, "10.9.9.9");
            return (await http.SendAsync(request)).StatusCode;
        }

        // A flood of junk from the same address (far beyond the limit of 3) ...
        for (var i = 0; i < 25; i++)
        {
            Assert.AreEqual(HttpStatusCode.Unauthorized, await PingAsync($"amkwa_{i:x12}_{Guid.NewGuid():N}"));
        }

        // ... does not lock out the genuine token from that address.
        Assert.AreEqual(HttpStatusCode.NoContent, await PingAsync(token));

        // Even someone hammering the genuine token's own prefix with wrong secrets cannot lock it out once it validated.
        var prefix = token.Split('_')[1];
        for (var i = 0; i < 5; i++)
        {
            Assert.AreEqual(HttpStatusCode.Unauthorized, await PingAsync($"amkwa_{prefix}_{Guid.NewGuid():N}"));
        }

        Assert.AreEqual(HttpStatusCode.NoContent, await PingAsync(token));
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Refused_tokens_are_audited_once_per_reason_and_never_with_the_token()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var (tenantId, admin, _) = await SeedAsync(provider);
        var (appId, _) = await CreateApplicationAsync(provider, tenantId, admin, "audited", "Api:Key", "v1");

        IssuedSoftwareClientToken issued;
        using (var scope = ScopeFor(provider, tenantId, admin))
        {
            var tokens = scope.ServiceProvider.GetRequiredService<ISoftwareClientTokenService>();
            issued = await tokens.IssueAsync(new IssueSoftwareClientTokenCommand(tenantId, appId, "Production", "audited-token", null, admin));
            await tokens.RevokeAsync(tenantId, issued.TokenId, admin);
        }

        var wrongSecret = $"amkw_{issued.TokenPrefix}_{new string('0', 64)}";
        using (var scope = provider.CreateScope())
        {
            var validator = scope.ServiceProvider.GetRequiredService<ISoftwareClientAuthenticationValidator>();
            var revoked = await validator.ValidateAsync(issued.Token, IPAddress.Parse("10.1.2.3"));
            Assert.AreEqual(TokenAuthenticationFailure.Revoked, revoked.Failure);
            Assert.AreEqual(TokenAuthenticationFailure.Revoked, (await validator.ValidateAsync(issued.Token, IPAddress.Parse("10.1.2.3"))).Failure);
            Assert.AreEqual(TokenAuthenticationFailure.WrongSecret, (await validator.ValidateAsync(wrongSecret, IPAddress.Parse("10.1.2.3"))).Failure);
            Assert.AreEqual(TokenAuthenticationFailure.UnknownToken, (await validator.ValidateAsync("amkw_ffffffffffff_00", null)).Failure);
            Assert.AreEqual(TokenAuthenticationFailure.Malformed, (await validator.ValidateAsync("not-a-token", null)).Failure);
        }

        using (var scope = ScopeFor(provider, tenantId, admin))
        {
            var entries = await scope.ServiceProvider.GetRequiredService<KeywardDbContext>().AuditEntries.AsNoTracking()
                .Where(a => a.TenantId == tenantId && a.Action == AuditAction.Login && a.ResourceId == issued.TokenId)
                .ToListAsync();

            Assert.HasCount(2, entries, "one entry per reason, the repeated revoked attempt is not written again");
            Assert.IsTrue(entries.All(e => e.ActorKind == ActorKind.SoftwareClient && e.ActorTokenId == issued.TokenId));
            Assert.IsTrue(entries.Any(e => e.Reason!.StartsWith(TokenAuthenticationAuditor.RefusedReasonPrefix + "Revoked", StringComparison.Ordinal)));
            Assert.IsTrue(entries.Any(e => e.Reason!.StartsWith(TokenAuthenticationAuditor.RefusedReasonPrefix + "WrongSecret", StringComparison.Ordinal)));
            Assert.IsTrue(entries.All(e => !e.Reason!.Contains(issued.Token, StringComparison.Ordinal) && !e.Reason!.Contains(wrongSecret, StringComparison.Ordinal)));
        }
    }

    [TestMethod, TestCategory("Integration")]
    public async Task The_tree_of_an_allowed_personal_vault_answers_and_an_overlong_name_is_a_bad_request()
    {
        await using var app = await AgentApiTests.StartAsync();
        if (app is null)
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var tenantId = Guid.NewGuid();
        var owner = Guid.NewGuid();
        await AgentApiTests.SeedTenantAsync(app.Services, tenantId, owner);
        Guid personal;
        using (var scope = AgentApiTests.ScopeFor(app.Services, tenantId, owner))
        {
            var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
            personal = await vaults.CreatePersonalVaultAsync(new CreatePersonalVaultCommand(owner, "Mine"));
            await vaults.SetAgentAccessAsync(owner, personal, allowed: true);
        }

        var client = app.GetTestClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer",
            await AgentApiTests.IssueAsync(app.Services, tenantId, owner, personal, AgentScopes.VaultList | AgentScopes.VaultWrite));

        var tree = await client.GetAsync($"{KeywardAgentApi.DefaultPrefix}/vaults/{personal}/tree");
        Assert.AreEqual(HttpStatusCode.OK, tree.StatusCode);
        Assert.AreEqual("Mine", (await tree.Content.ReadFromJsonAsync<AgentVaultTreeResponse>())!.VaultName);

        var created = await client.PostAsJsonAsync($"{KeywardAgentApi.DefaultPrefix}/vaults/{personal}/items",
            new { type = "Generic", name = new string('n', 257), value = "v" });
        Assert.AreEqual(HttpStatusCode.BadRequest, created.StatusCode);
        Assert.AreEqual(HttpStatusCode.Created, (await client.PostAsJsonAsync($"{KeywardAgentApi.DefaultPrefix}/vaults/{personal}/items",
            new { type = "Generic", name = new string('n', 256), value = "v" })).StatusCode);
    }

    [TestMethod, TestCategory("Integration")]
    public async Task A_single_tenant_host_answers_a_foreign_tenants_token_with_403()
    {
        var hostTenant = Guid.NewGuid();
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddKeyward(TestConfig.ConnectionString, RandomNumberGenerator.GetBytes(32), "test-kek:v1");
        builder.Services.AddKeywardAgentApi();
        builder.Services.RemoveAll<IHostedService>();
        await using var app = builder.Build();
        app.UseRateLimiter();
        app.UseAuthentication();
        app.UseAuthorization();
        app.UseKeywardSingleTenant(hostTenant);
        app.MapKeywardAgentApi();

        using (var probe = app.Services.CreateScope())
        {
            if (!await probe.ServiceProvider.GetRequiredService<KeywardDbContext>().Database.CanConnectAsync())
            {
                Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
                return;
            }
        }

        await app.StartAsync();

        var foreignTenant = Guid.NewGuid();
        var user = Guid.NewGuid();
        await AgentApiTests.SeedTenantAsync(app.Services, foreignTenant, user);
        Guid vault;
        using (var scope = AgentApiTests.ScopeFor(app.Services, foreignTenant, user))
        {
            vault = await scope.ServiceProvider.GetRequiredService<IVaultService>().CreateTenantVaultAsync(new CreateTenantVaultCommand(user, foreignTenant, "v"));
            await scope.ServiceProvider.GetRequiredService<IVaultService>().SetAgentAccessAsync(user, vault, allowed: true);
        }

        var client = app.GetTestClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer",
            await AgentApiTests.IssueAsync(app.Services, foreignTenant, user, vault, AgentScopes.VaultList));

        Assert.AreEqual(HttpStatusCode.Forbidden, (await client.GetAsync($"{KeywardAgentApi.DefaultPrefix}/vaults")).StatusCode);
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Version_numbers_continue_from_the_highest_stored_one_and_concurrent_stores_all_land()
    {
        await using var provider = BuildProvider();
        if (!await CanConnectAsync(provider))
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var (tenantId, admin, _) = await SeedAsync(provider);
        var (appId, _) = await CreateApplicationAsync(provider, tenantId, admin, "versions", "Api:Key", "v1");

        using (var scope = ScopeFor(provider, tenantId, admin))
        {
            var secrets = scope.ServiceProvider.GetRequiredService<ISoftwareSecretService>();
            Assert.AreEqual(2, (await secrets.StoreAsync(new StoreSoftwareSecretCommand(tenantId, appId, "Production", "Api:Key", "v2", admin))).VersionNumber);

            // Prune the oldest version: «count + 1» would now collide with version 2.
            var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
            var oldest = await db.SecretVersions.Where(v => v.VersionNumber == 1
                && db.SecretValues.Any(x => x.Id == v.SecretValueId
                    && db.SoftwareSecrets.Any(s => s.Id == x.SoftwareSecretId && s.ProjectId == appId))).SingleAsync();
            db.SecretVersions.Remove(oldest);
            await db.SaveChangesAsync();

            var stored = await secrets.StoreAsync(new StoreSoftwareSecretCommand(tenantId, appId, "Production", "Api:Key", "v3", admin));
            Assert.AreEqual(3, stored.VersionNumber);
            Assert.AreEqual("v3", await secrets.ReadAsync(new ReadSoftwareSecretQuery(tenantId, appId, "Production", "Api:Key", admin)));
        }

        // Concurrent stores without a precondition («last write wins») all land instead of failing on the unique index.
        var writers = Enumerable.Range(0, 4).Select(async i =>
        {
            using var scope = ScopeFor(provider, tenantId, admin);
            await scope.ServiceProvider.GetRequiredService<ISoftwareSecretService>()
                .StoreAsync(new StoreSoftwareSecretCommand(tenantId, appId, "Test", "Race:Key", $"r{i}", admin));
        });
        await Task.WhenAll(writers);

        using (var scope = ScopeFor(provider, tenantId, admin))
        {
            var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
            var numbers = await db.SecretVersions.AsNoTracking()
                .Where(v => db.SecretValues.Any(x => x.Id == v.SecretValueId
                    && db.SoftwareSecrets.Any(s => s.Id == x.SoftwareSecretId && s.ProjectId == appId && s.Key == SecretKeyOf("Race:Key"))))
                .Select(v => v.VersionNumber)
                .ToListAsync();
            CollectionAssert.AreEquivalent(new[] { 1, 2, 3, 4 }, numbers);
        }
    }

    [TestMethod, TestCategory("Unit")]
    public void A_rotation_date_is_presented_as_the_calendar_date_that_was_entered()
    {
        var entered = new DateOnly(2026, 12, 31);
        var stored = SecretValue.EndOfDay(entered);

        Assert.AreEqual(entered, SecretValue.CalendarDate(stored));
        Assert.AreEqual(entered, new SecretEnvironmentValue("Production", true, null, ExpiresAt: stored).ExpiresOn);
        Assert.IsNull(new SecretEnvironmentValue("Production", false, null).ExpiresOn);

        // The trap it avoids: east of UTC the stored instant is already the next day.
        Assert.AreEqual(new DateOnly(2027, 1, 1), DateOnly.FromDateTime(stored.ToOffset(TimeSpan.FromHours(1)).DateTime));
    }

    [TestMethod, TestCategory("Unit")]
    public void An_unrestricted_agent_api_is_warned_about_and_a_proxy_network_in_the_list_is_rejected()
    {
        var log = new ListLogger();

        KeywardNetworkPolicyStartupLog<AgentNetworkPolicy>.Report(AgentNetworkPolicy.Parse(null), log);
        Assert.IsTrue(log.Entries.Any(e => e.Level == LogLevel.Warning && e.Message.Contains("Keyward:Agent:AllowedNetworks", StringComparison.Ordinal)));

        log.Entries.Clear();
        KeywardNetworkPolicyStartupLog<AgentNetworkPolicy>.Report(AgentNetworkPolicy.Parse("10.1.0.0/24"), log);
        Assert.IsTrue(log.Entries.Any(e => e.Level == LogLevel.Information && e.Message.Contains("KnownProxies", StringComparison.Ordinal)),
            "a restriction without a trusted proxy says that the proxy guard is blind");

        var withProxyNetwork = SoftwareClientNetworkPolicy.Parse("10.0.0.0/16", knownProxyNetworks: [System.Net.IPNetwork.Parse("10.0.5.0/24")]);
        Assert.IsFalse(withProxyNetwork.IsValid);
        StringAssert.Contains(withProxyNetwork.Error, "KnownIPNetworks");
        Assert.IsFalse(withProxyNetwork.Allows(IPAddress.Parse("10.0.1.1")), "fail closed");

        var withProxy = AgentNetworkPolicy.Parse("10.0.0.0/16", [IPAddress.Parse("10.0.0.9")]);
        Assert.IsFalse(withProxy.IsValid);
        Assert.IsTrue(AgentNetworkPolicy.Parse("10.1.0.0/16", [IPAddress.Parse("10.0.0.9")]).ProxyGuardActive);
    }

    // --- harness ---

    private static async Task<WebApplication?> StartManagementAsync()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddKeyward(TestConfig.ConnectionString, RandomNumberGenerator.GetBytes(32), "test-kek:v1");
        builder.Services.RemoveAll<IHostedService>();
        var app = builder.Build();

        // Test only: the signed-in user comes from a header (a host derives it from its auth cookie).
        app.Use((context, next) =>
        {
            if (context.Request.Headers.TryGetValue(UserHeader, out var user))
            {
                context.RequestServices.GetRequiredService<IUserScopeSetter>().SetUser(Guid.Parse(user.ToString()));
            }

            return next();
        });
        app.MapKeywardApi();

        using (var probe = app.Services.CreateScope())
        {
            if (!await probe.ServiceProvider.GetRequiredService<KeywardDbContext>().Database.CanConnectAsync())
            {
                await app.DisposeAsync();
                return null;
            }
        }

        await app.StartAsync();
        return app;
    }

    private static HttpClient ClientFor(WebApplication app, Guid userId)
    {
        var client = app.GetTestClient();
        client.DefaultRequestHeaders.Add(UserHeader, userId.ToString());
        return client;
    }

    private static HttpRequestMessage Deliberate(HttpMethod method, string url)
    {
        var request = new HttpRequestMessage(method, url);
        request.Headers.Add(KeywardApiDefaults.ManagementRequestHeader, "1");
        return request;
    }

    private static ServiceProvider BuildProvider()
    {
        var services = new ServiceCollection();
        services.AddKeyward(TestConfig.ConnectionString, RandomNumberGenerator.GetBytes(32), "test-kek:v1");
        return services.BuildServiceProvider();
    }

    private static async Task<bool> CanConnectAsync(IServiceProvider provider)
    {
        using var scope = provider.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<KeywardDbContext>().Database.CanConnectAsync();
    }

    private static IServiceScope ScopeFor(IServiceProvider provider, Guid tenantId, Guid userId)
    {
        var scope = provider.CreateScope();
        scope.ServiceProvider.GetRequiredService<ITenantScopeSetter>().SetTenant(tenantId);
        scope.ServiceProvider.GetRequiredService<IUserScopeSetter>().SetUser(userId);
        return scope;
    }

    private static Core.Domain.ValueObjects.SecretKey SecretKeyOf(string key) => Core.Domain.ValueObjects.SecretKey.Create(key);

    // A tenant with a tenant admin (a software operator) and a plain member.
    private static async Task<(Guid TenantId, Guid Admin, Guid Member)> SeedAsync(IServiceProvider provider)
    {
        var (tenantId, admin, member) = (Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid());
        using var scope = provider.CreateScope();
        scope.ServiceProvider.GetRequiredService<ITenantScopeSetter>().SetTenant(tenantId);
        var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
        db.Tenants.Add(new Tenant(tenantId, "review3-api", isSystemTenant: false, DateTimeOffset.UtcNow));
        foreach (var (userId, role) in new[] { (admin, TenantRole.TenantAdmin), (member, TenantRole.Member) })
        {
            db.Users.Add(new AppUser(userId, issuer: null, externalId: userId.ToString(), displayName: $"user-{userId:N}", isSystemAdmin: false, DateTimeOffset.UtcNow));
            db.TenantMemberships.Add(new TenantMembership(Guid.NewGuid(), tenantId, userId, role, DateTimeOffset.UtcNow));
        }

        await db.SaveChangesAsync();
        return (tenantId, admin, member);
    }

    // An application with one value in Production and one issued token there.
    private static async Task<(Guid AppId, Guid TokenId)> CreateApplicationAsync(
        IServiceProvider provider, Guid tenantId, Guid admin, string name, string key, string value)
    {
        using var scope = ScopeFor(provider, tenantId, admin);
        var appId = await scope.ServiceProvider.GetRequiredService<IProjectService>().CreateAsync(tenantId, name, admin);
        await scope.ServiceProvider.GetRequiredService<ISoftwareSecretService>()
            .StoreAsync(new StoreSoftwareSecretCommand(tenantId, appId, "Production", key, value, admin));
        var issued = await scope.ServiceProvider.GetRequiredService<ISoftwareClientTokenService>()
            .IssueAsync(new IssueSoftwareClientTokenCommand(tenantId, appId, "Production", $"{name}-issued", null, admin));
        return (appId, issued.TokenId);
    }

    private sealed class ListLogger : ILogger
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            Entries.Add((logLevel, formatter(state, exception)));
    }
}
