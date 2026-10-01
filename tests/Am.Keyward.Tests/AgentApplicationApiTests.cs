using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Am.Keyward.Contracts;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Agent;
using Am.Keyward.Core.Domain.Identity;
using Am.Keyward.Core.Domain.ValueObjects;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using static Am.Keyward.Tests.AgentApiTests;

namespace Am.Keyward.Tests;

/// <summary>
/// The application endpoints of the agent API over real HTTP: the BotWatch use case end to end, write-only values
/// (no response and no log line carries one), reach (allowlist + own creations, everything else 404), the permission
/// gate, validation identical to the UI, If-Match / If-None-Match, rename/delete only for the token's own empty
/// placeholders, audit as the agent, no app-token endpoints, and the network restriction.
/// </summary>
[TestClass]
public class AgentApplicationApiTests
{
    private const string Base = "/keyward/api/v1/agent";
    private const string ApiKey = "PionexOwnerBotWatch:ApiKey";
    private const string ApiSecret = "PionexOwnerBotWatch:ApiSecret";

    [TestMethod, TestCategory("Integration")]
    public async Task Assistant_sets_up_BotWatch_and_never_sees_a_value()
    {
        var logs = new CapturingLoggerProvider();
        await using var app = await StartAsync(services =>
        {
            services.AddSingleton<ILoggerProvider>(logs);
            services.Configure<LoggerFilterOptions>(o => o.MinLevel = LogLevel.Trace);
        });
        if (app is null)
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var (tenantId, manager, _) = await SeedAsync(app.Services);
        var (token, tokenId) = await IssueAsync(app.Services, tenantId, manager, create: true);
        var client = Client(app, token);
        var secretValue = "sk-live-" + Guid.NewGuid().ToString("N");
        var keyValue = "pk-live-" + Guid.NewGuid().ToString("N");
        var bodies = new List<string>();

        async Task<HttpResponseMessage> Send(HttpRequestMessage request)
        {
            var response = await client.SendAsync(request);
            bodies.Add(await response.Content.ReadAsStringAsync() + string.Join("|", response.Headers.Select(h => h.Key + "=" + string.Join(",", h.Value))));
            return response;
        }

        // The application, with the environment the console needs.
        var created = await Send(Post($"{Base}/applications", new AgentCreateApplicationRequest("Am.PionexCom.Cmd.BotWatch", ["Production", "Staging"])));
        Assert.AreEqual(HttpStatusCode.Created, created.StatusCode);
        var application = (await created.Content.ReadFromJsonAsync<AgentApplicationResponse>())!;
        Assert.IsTrue(application.CreatedByThisToken);
        Assert.AreEqual($"/amkeyward/applications?app={application.Id}&tab=data", application.Link);
        Assert.AreEqual($"/amkeyward/applications?app={application.Id}&tab=tokens", application.TokensLink);
        CollectionAssert.IsSubsetOf(new[] { "Production", "Staging" }, application.Environments.ToArray());

        // One placeholder for a person to fill, one value the assistant legitimately holds.
        var placeholder = await Send(Post($"{Base}/applications/{application.Id}/secrets", new AgentCreateSecretRequest(ApiKey)));
        Assert.AreEqual(HttpStatusCode.Created, placeholder.StatusCode);
        Assert.IsFalse((await placeholder.Content.ReadFromJsonAsync<AgentSecretWrittenResponse>())!.ValueSet);

        var withValue = await Send(Post($"{Base}/applications/{application.Id}/secrets", new AgentCreateSecretRequest(ApiSecret, "Production", secretValue)));
        Assert.AreEqual(HttpStatusCode.Created, withValue.StatusCode);
        var written = (await withValue.Content.ReadFromJsonAsync<AgentSecretWrittenResponse>())!;
        Assert.IsTrue(written.ValueSet);
        Assert.AreEqual($"\"{written.VersionId}\"", withValue.Headers.ETag!.Tag);

        // The listing tells «set / not set» and the version, never the value.
        var listed = (await ListAsync(client)).Single(a => a.Id == application.Id);
        var secretState = listed.Keys.Single(k => k.Key == ApiSecret).Values.Single(v => v.Environment == "Production");
        Assert.IsTrue(secretState.ValueSet);
        Assert.AreEqual(written.VersionId, secretState.VersionId);
        Assert.IsFalse(listed.Keys.Single(k => k.Key == ApiKey).Values.Any(v => v.ValueSet));

        // Setting a value needs a precondition: none → 428; «no value yet» → 200; the same again → 412.
        var url = $"{Base}/applications/{application.Id}/secrets/{Uri.EscapeDataString(ApiKey)}";
        Assert.AreEqual((HttpStatusCode)428, (await Send(Put(url, keyValue))).StatusCode);
        var first = await Send(Put(url, keyValue, ifNoneMatch: true));
        Assert.AreEqual(HttpStatusCode.OK, first.StatusCode);
        var firstVersion = (await first.Content.ReadFromJsonAsync<AgentSecretWrittenResponse>())!.VersionId!.Value;
        Assert.AreEqual(HttpStatusCode.PreconditionFailed, (await Send(Put(url, keyValue, ifNoneMatch: true))).StatusCode);

        // If-Match: the current version wins once; the stale one is refused.
        var second = await Send(Put(url, keyValue + "-2", ifMatch: firstVersion));
        Assert.AreEqual(HttpStatusCode.OK, second.StatusCode);
        Assert.AreEqual(HttpStatusCode.PreconditionFailed, (await Send(Put(url, keyValue + "-3", ifMatch: firstVersion))).StatusCode);

        // Racing writers from the same version: exactly one wins, the others get 412.
        var current = (await ListAsync(client)).Single(a => a.Id == application.Id)
            .Keys.Single(k => k.Key == ApiKey).Values.Single(v => v.Environment == "Production").VersionId!.Value;
        var race = await Task.WhenAll(Enumerable.Range(1, 5).Select(i => Client(app, token).SendAsync(Put(url, $"{keyValue}-race{i}", ifMatch: current))));
        Assert.AreEqual(1, race.Count(r => r.StatusCode == HttpStatusCode.OK));
        Assert.AreEqual(4, race.Count(r => r.StatusCode == HttpStatusCode.PreconditionFailed));

        // The values really are stored — a person sees them in the UI.
        using (var scope = ScopeFor(app.Services, tenantId, manager))
        {
            var detail = await scope.ServiceProvider.GetRequiredService<ISoftwareSecretService>().GetSecretAsync(tenantId, application.Id, ApiSecret);
            Assert.AreEqual(secretValue, detail!.Environments.Single(e => e.Environment == "Production").Value);
        }

        // Write-only: no response and no log line carries a value.
        foreach (var body in bodies)
        {
            Assert.DoesNotContain(secretValue, body);
            Assert.DoesNotContain(keyValue, body);
        }

        var logText = string.Join("\n", logs.Messages);
        Assert.IsGreaterThan(0, logs.Messages.Count, "The capture must actually see the host's logs.");
        Assert.DoesNotContain(secretValue, logText);
        Assert.DoesNotContain(keyValue, logText);

        // Every change is audited as the agent, with its token.
        using (var scope = ScopeFor(app.Services, tenantId, manager))
        {
            var entries = await scope.ServiceProvider.GetRequiredService<KeywardDbContext>().AuditEntries.AsNoTracking()
                .Where(a => a.TenantId == tenantId && a.ActorTokenId == tokenId)
                .ToListAsync();
            Assert.IsTrue(entries.All(e => e.ActorKind == ActorKind.Agent));
            Assert.IsTrue(entries.Any(e => e.ResourceType == "Project" && e.Action == AuditAction.Create && e.ResourceId == application.Id));
            Assert.IsTrue(entries.Any(e => e.ResourceType == "Environment" && e.Action == AuditAction.Create));
            Assert.IsTrue(entries.Any(e => e.ResourceType == "SoftwareSecret" && e.Action == AuditAction.Create));
            Assert.IsGreaterThanOrEqualTo(4, entries.Count(e => e.ResourceType == "SoftwareSecret" && e.Action == AuditAction.Update));
            Assert.IsTrue(entries.Any(e => e.ResourceType == "ApplicationList" && e.Action == AuditAction.Read));
        }
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Reach_is_the_allowlist_plus_own_creations_and_everything_else_is_404()
    {
        await using var app = await StartAsync();
        if (app is null)
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var (tenantId, manager, _) = await SeedAsync(app.Services);
        Guid allowed, other, vault;
        using (var scope = ScopeFor(app.Services, tenantId, manager))
        {
            var projects = scope.ServiceProvider.GetRequiredService<IProjectService>();
            allowed = await projects.CreateAsync(tenantId, "allowed", manager);
            other = await projects.CreateAsync(tenantId, "other", manager);
            var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
            vault = await vaults.CreateTenantVaultAsync(new CreateTenantVaultCommand(manager, tenantId, "KI-Tresor"));
            await vaults.SetAgentAccessAsync(manager, vault, allowed: true);
        }

        var (foreignTenant, foreignManager, _) = await SeedAsync(app.Services);
        Guid foreign;
        using (var scope = ScopeFor(app.Services, foreignTenant, foreignManager))
        {
            foreign = await scope.ServiceProvider.GetRequiredService<IProjectService>().CreateAsync(foreignTenant, "foreign", foreignManager);
        }

        var (token, _) = await IssueAsync(app.Services, tenantId, manager, applicationId: allowed);
        var client = Client(app, token);

        CollectionAssert.AreEqual(new[] { allowed }, (await ListAsync(client)).Select(a => a.Id).ToArray());
        Assert.AreEqual(HttpStatusCode.OK, (await client.GetAsync($"{Base}/applications/{allowed}")).StatusCode);

        // Not on the allowlist, another tenant's, or missing: all the same 404, on every endpoint.
        foreach (var unreachable in new[] { other, foreign, Guid.NewGuid() })
        {
            Assert.AreEqual(HttpStatusCode.NotFound, (await client.GetAsync($"{Base}/applications/{unreachable}")).StatusCode);
            Assert.AreEqual(HttpStatusCode.NotFound, (await client.SendAsync(Post($"{Base}/applications/{unreachable}/secrets", new AgentCreateSecretRequest("A:B")))).StatusCode);
            Assert.AreEqual(HttpStatusCode.NotFound, (await client.SendAsync(Post($"{Base}/applications/{unreachable}/environments", new AgentAddEnvironmentRequest("Staging")))).StatusCode);
            Assert.AreEqual(HttpStatusCode.NotFound, (await client.SendAsync(Put($"{Base}/applications/{unreachable}/secrets/A:B", "v", ifNoneMatch: true))).StatusCode);
            Assert.AreEqual(HttpStatusCode.NotFound, (await client.DeleteAsync($"{Base}/applications/{unreachable}")).StatusCode);
        }

        // Without «may create new applications» the token cannot create one.
        Assert.AreEqual(HttpStatusCode.Forbidden, (await client.SendAsync(Post($"{Base}/applications", new AgentCreateApplicationRequest("new")))).StatusCode);

        // App tokens stay human-only: an agent may read their metadata (never a value), but nothing issues one.
        var tokensResponse = await client.GetAsync($"{Base}/applications/{allowed}/tokens");
        Assert.AreEqual(HttpStatusCode.OK, tokensResponse.StatusCode);
        var appTokens = (await tokensResponse.Content.ReadFromJsonAsync<List<AgentClientTokenResponse>>())!;
        Assert.IsTrue(appTokens.Count > 0 && appTokens.All(t => t.Status == "Pending"));
        Assert.DoesNotContain("amkw_", await tokensResponse.Content.ReadAsStringAsync());
        Assert.AreEqual(HttpStatusCode.MethodNotAllowed, (await client.SendAsync(Post($"{Base}/applications/{allowed}/tokens", new { environment = "Production" }))).StatusCode);
        Assert.AreEqual(HttpStatusCode.NotFound, (await client.SendAsync(Post($"{Base}/applications/{allowed}/tokens/issue", new { environment = "Production" }))).StatusCode);
        Assert.AreEqual(HttpStatusCode.OK, (await client.GetAsync($"{Base}/applications/{allowed}/statistics?days=7")).StatusCode);
        Assert.AreEqual(HttpStatusCode.NotFound, (await client.GetAsync($"{Base}/applications/{other}/tokens")).StatusCode);
        Assert.AreEqual(HttpStatusCode.NotFound, (await client.GetAsync($"{Base}/applications/{other}/statistics")).StatusCode);

        // A vault-only token: the collection says «not permitted», a single application stays a 404.
        var vaultOnly = Client(app, await AgentApiTests.IssueAsync(app.Services, tenantId, manager, vault, AgentScopes.VaultList));
        Assert.AreEqual(HttpStatusCode.Forbidden, (await vaultOnly.GetAsync($"{Base}/applications")).StatusCode);
        Assert.AreEqual(HttpStatusCode.NotFound, (await vaultOnly.GetAsync($"{Base}/applications/{allowed}")).StatusCode);

        // The permission follows the user's role on every request.
        await SetSoftwareManagerAsync(app.Services, tenantId, manager, false);
        Assert.AreEqual(HttpStatusCode.Forbidden, (await client.GetAsync($"{Base}/applications")).StatusCode);
        Assert.AreEqual(HttpStatusCode.NotFound, (await client.GetAsync($"{Base}/applications/{allowed}")).StatusCode);
        await SetSoftwareManagerAsync(app.Services, tenantId, manager, true);
        Assert.AreEqual(HttpStatusCode.OK, (await client.GetAsync($"{Base}/applications/{allowed}")).StatusCode);

        // And a revoked token stops at authentication.
        using (var scope = ScopeFor(app.Services, tenantId, manager))
        {
            var tokens = scope.ServiceProvider.GetRequiredService<IAgentTokenService>();
            var id = (await tokens.ListAsync(manager, tenantId)).Single(t => t.ApplicationIds.Contains(allowed)).Id;
            await tokens.RevokeAsync(manager, tenantId, id);
        }

        Assert.AreEqual(HttpStatusCode.Unauthorized, (await client.GetAsync($"{Base}/applications")).StatusCode);
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Validation_matches_the_UI_and_only_own_empty_placeholders_can_be_renamed_or_deleted()
    {
        await using var app = await StartAsync();
        if (app is null)
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var (tenantId, manager, _) = await SeedAsync(app.Services);
        Guid byPerson;
        using (var scope = ScopeFor(app.Services, tenantId, manager))
        {
            byPerson = await scope.ServiceProvider.GetRequiredService<IProjectService>().CreateAsync(tenantId, "by-person", manager);
            await scope.ServiceProvider.GetRequiredService<ISoftwareSecretService>().CreateSecretAsync(tenantId, byPerson, "Person:Key", manager);
        }

        var (token, _) = await IssueAsync(app.Services, tenantId, manager, applicationId: byPerson, create: true);
        var client = Client(app, token);

        // The same rule set as the UI: the very message the shared validators produce.
        Assert.AreEqual(Message(() => SecretKey.Create("has space")),
            await ProblemAsync(client, Post($"{Base}/applications/{byPerson}/secrets", new AgentCreateSecretRequest("has space")), HttpStatusCode.BadRequest));
        Assert.AreEqual(Message(() => EnvironmentName.Create("  ")),
            await ProblemAsync(client, Post($"{Base}/applications/{byPerson}/environments", new AgentAddEnvironmentRequest("  ")), HttpStatusCode.BadRequest));
        await ProblemAsync(client, Post($"{Base}/applications", new AgentCreateApplicationRequest(" ")), HttpStatusCode.BadRequest);
        string duplicateMessage;
        using (var scope = ScopeFor(app.Services, tenantId, manager))
        {
            var ex = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() =>
                scope.ServiceProvider.GetRequiredService<IProjectService>().CreateAsync(tenantId, "by-person", manager));
            duplicateMessage = ex.Message;
        }

        Assert.AreEqual(duplicateMessage,
            await ProblemAsync(client, Post($"{Base}/applications", new AgentCreateApplicationRequest("by-person")), HttpStatusCode.Conflict));
        await ProblemAsync(client, Post($"{Base}/applications/{byPerson}/secrets", new AgentCreateSecretRequest("person:key")), HttpStatusCode.Conflict);
        await ProblemAsync(client, Post($"{Base}/applications/{byPerson}/secrets", new AgentCreateSecretRequest("A:B", "Nowhere", "v")), HttpStatusCode.BadRequest);
        await ProblemAsync(client, Post($"{Base}/applications/{byPerson}/secrets", new AgentCreateSecretRequest("A:B", null, "v")), HttpStatusCode.BadRequest);
        Assert.AreEqual(HttpStatusCode.Created, (await client.SendAsync(Post($"{Base}/applications/{byPerson}/environments", new AgentAddEnvironmentRequest("Staging")))).StatusCode);
        await ProblemAsync(client, Post($"{Base}/applications/{byPerson}/environments", new AgentAddEnvironmentRequest("staging")), HttpStatusCode.Conflict);

        // Own placeholder: rename and delete are allowed.
        var own = $"{Base}/applications/{byPerson}/secrets";
        Assert.AreEqual(HttpStatusCode.Created, (await client.SendAsync(Post(own, new AgentCreateSecretRequest("Typo:Kye")))).StatusCode);
        Assert.AreEqual(HttpStatusCode.NoContent, (await client.SendAsync(Patch($"{own}/Typo:Kye", new AgentRenameSecretRequest("Typo:Key")))).StatusCode);
        Assert.AreEqual(HttpStatusCode.NoContent, (await client.DeleteAsync($"{own}/Typo:Key")).StatusCode);

        // Someone else's key, or an own key that holds a value: a person's job.
        await ProblemAsync(client, Patch($"{own}/Person:Key", new AgentRenameSecretRequest("Person:Other")), HttpStatusCode.Forbidden);
        await ProblemAsync(client, new HttpRequestMessage(HttpMethod.Delete, $"{own}/Person:Key"), HttpStatusCode.Forbidden);
        Assert.AreEqual(HttpStatusCode.Created, (await client.SendAsync(Post(own, new AgentCreateSecretRequest("Filled:Key", "Production", "v")))).StatusCode);
        await ProblemAsync(client, new HttpRequestMessage(HttpMethod.Delete, $"{own}/Filled:Key"), HttpStatusCode.Forbidden);
        await ProblemAsync(client, Patch($"{own}/Missing:Key", new AgentRenameSecretRequest("X:Y")), HttpStatusCode.NotFound);

        // Applications: not the one a person created; an own one only while it is empty.
        await ProblemAsync(client, Patch($"{Base}/applications/{byPerson}", new AgentRenameApplicationRequest("renamed")), HttpStatusCode.Forbidden);
        await ProblemAsync(client, new HttpRequestMessage(HttpMethod.Delete, $"{Base}/applications/{byPerson}"), HttpStatusCode.Forbidden);

        var emptyResponse = await client.SendAsync(Post($"{Base}/applications", new AgentCreateApplicationRequest("agent-empty")));
        var empty = (await emptyResponse.Content.ReadFromJsonAsync<AgentApplicationResponse>())!;
        Assert.AreEqual(HttpStatusCode.OK, (await client.SendAsync(Patch($"{Base}/applications/{empty.Id}", new AgentRenameApplicationRequest("agent-empty-2")))).StatusCode);
        Assert.AreEqual(HttpStatusCode.NoContent, (await client.DeleteAsync($"{Base}/applications/{empty.Id}")).StatusCode);

        var filledResponse = await client.SendAsync(Post($"{Base}/applications", new AgentCreateApplicationRequest("agent-filled")));
        var filled = (await filledResponse.Content.ReadFromJsonAsync<AgentApplicationResponse>())!;
        Assert.AreEqual(HttpStatusCode.Created, (await client.SendAsync(Post($"{Base}/applications/{filled.Id}/secrets", new AgentCreateSecretRequest("A:B", "Production", "v")))).StatusCode);
        await ProblemAsync(client, new HttpRequestMessage(HttpMethod.Delete, $"{Base}/applications/{filled.Id}"), HttpStatusCode.Forbidden);

        // An own application in which a person issued an app token is a person's job too.
        var issuedResponse = await client.SendAsync(Post($"{Base}/applications", new AgentCreateApplicationRequest("agent-token-issued")));
        var withToken = (await issuedResponse.Content.ReadFromJsonAsync<AgentApplicationResponse>())!;
        using (var scope = ScopeFor(app.Services, tenantId, manager))
        {
            await scope.ServiceProvider.GetRequiredService<ISoftwareClientTokenService>().IssueAsync(
                new IssueSoftwareClientTokenCommand(tenantId, withToken.Id, "Production", "deploy", null, manager));
        }

        await ProblemAsync(client, new HttpRequestMessage(HttpMethod.Delete, $"{Base}/applications/{withToken.Id}"), HttpStatusCode.Forbidden);
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Network_restriction_applies_to_the_application_endpoints()
    {
        await using var app = await StartAsync(agentOptions: o => o.AllowedNetworks = "10.1.0.0/23");
        if (app is null)
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var (tenantId, manager, _) = await SeedAsync(app.Services);
        var (token, _) = await IssueAsync(app.Services, tenantId, manager, create: true);

        var fromProxy = Client(app, token);
        fromProxy.DefaultRequestHeaders.Add(TestClientIpHeader, "172.16.0.93");
        Assert.AreEqual(HttpStatusCode.Forbidden, (await fromProxy.GetAsync($"{Base}/applications")).StatusCode);
        Assert.AreEqual(HttpStatusCode.Forbidden, (await fromProxy.SendAsync(Post($"{Base}/applications", new AgentCreateApplicationRequest("x")))).StatusCode);

        var fromLan = Client(app, token);
        fromLan.DefaultRequestHeaders.Add(TestClientIpHeader, "10.1.0.26");
        Assert.AreEqual(HttpStatusCode.OK, (await fromLan.GetAsync($"{Base}/applications")).StatusCode);
    }

    private static HttpClient Client(WebApplication app, string token)
    {
        var client = app.GetTestClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client;
    }

    private static async Task<List<AgentApplicationResponse>> ListAsync(HttpClient client)
    {
        var response = await client.GetAsync($"{Base}/applications");
        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<List<AgentApplicationResponse>>())!;
    }

    private static HttpRequestMessage Post(string url, object body) => new(HttpMethod.Post, url) { Content = JsonContent.Create(body) };

    private static HttpRequestMessage Patch(string url, object body) => new(HttpMethod.Patch, url) { Content = JsonContent.Create(body) };

    private static HttpRequestMessage Put(string url, string value, Guid? ifMatch = null, bool ifNoneMatch = false)
    {
        var request = new HttpRequestMessage(HttpMethod.Put, url) { Content = JsonContent.Create(new AgentSetSecretValueRequest("Production", value)) };
        if (ifMatch is { } version)
        {
            request.Headers.IfMatch.Add(new EntityTagHeaderValue($"\"{version}\""));
        }

        if (ifNoneMatch)
        {
            request.Headers.IfNoneMatch.Add(EntityTagHeaderValue.Any);
        }

        return request;
    }

    private static async Task<string> ProblemAsync(HttpClient client, HttpRequestMessage request, HttpStatusCode expected)
    {
        var response = await client.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();
        Assert.AreEqual(expected, response.StatusCode, body);
        return JsonDocument.Parse(body).RootElement.GetProperty("title").GetString()!;
    }

    private static string Message(Action action)
    {
        try
        {
            action();
        }
        catch (ArgumentException ex)
        {
            return ex.Message;
        }

        throw new AssertFailedException("The validator accepted the input.");
    }

    private static async Task<(string Token, Guid TokenId)> IssueAsync(
        IServiceProvider services, Guid tenantId, Guid userId, Guid? applicationId = null, bool create = false)
    {
        using var scope = ScopeFor(services, tenantId, userId);
        var issued = await scope.ServiceProvider.GetRequiredService<IAgentTokenService>().IssueAsync(new IssueAgentTokenCommand(
            userId, tenantId, $"agent-{Guid.NewGuid():N}", AgentScopes.ManageApplications, [],
            ApplicationIds: applicationId is { } id ? [id] : [], MayCreateApplications: create));
        return (issued.Token, issued.TokenId);
    }

    // A tenant with a software manager (a plain member who may manage applications) — the role the permission needs.
    private static async Task<(Guid TenantId, Guid Manager, Guid Member)> SeedAsync(IServiceProvider services)
    {
        var tenantId = Guid.NewGuid();
        var manager = Guid.NewGuid();
        var member = Guid.NewGuid();
        using var scope = services.CreateScope();
        scope.ServiceProvider.GetRequiredService<ITenantScopeSetter>().SetTenant(tenantId);
        var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
        db.Tenants.Add(new Tenant(tenantId, "agent-apps-api-test", isSystemTenant: false, DateTimeOffset.UtcNow));
        var managerUser = new AppUser(manager, issuer: null, externalId: $"user-{manager:N}", displayName: "manager", isSystemAdmin: false, DateTimeOffset.UtcNow);
        managerUser.GrantSoftwareManager();
        db.Users.Add(managerUser);
        db.Users.Add(new AppUser(member, issuer: null, externalId: $"user-{member:N}", displayName: "member", isSystemAdmin: false, DateTimeOffset.UtcNow));
        db.TenantMemberships.Add(new TenantMembership(Guid.NewGuid(), tenantId, manager, TenantRole.Member, DateTimeOffset.UtcNow));
        db.TenantMemberships.Add(new TenantMembership(Guid.NewGuid(), tenantId, member, TenantRole.Member, DateTimeOffset.UtcNow));
        await db.SaveChangesAsync();
        return (tenantId, manager, member);
    }

    private static async Task SetSoftwareManagerAsync(IServiceProvider services, Guid tenantId, Guid userId, bool isManager)
    {
        using var scope = ScopeFor(services, tenantId, userId);
        var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
        var user = await db.Users.SingleAsync(u => u.Id == userId);
        if (isManager)
        {
            user.GrantSoftwareManager();
        }
        else
        {
            user.RevokeSoftwareManager();
        }

        await db.SaveChangesAsync();
    }

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        public ConcurrentQueue<string> Messages { get; } = new();

        public ILogger CreateLogger(string categoryName) => new Capturing(Messages);

        public void Dispose()
        {
        }

        private sealed class Capturing(ConcurrentQueue<string> messages) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
                messages.Enqueue(formatter(state, exception) + " " + state + " " + exception);
        }
    }
}
