using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Am.Keyward.Contracts;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Agent;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using static Am.Keyward.Tests.AgentApiTests;

namespace Am.Keyward.Tests;

/// <summary>
/// The reveal flow over real HTTP: nothing is revealed before the token user approves; an approved value is handed
/// out exactly once within its window; every step is audited with the right actor; the notification carries the
/// request but never the secret.
/// </summary>
[TestClass]
public class RevealFlowTests
{
    private const string Password = "Pa55-only-after-approval";

    [TestMethod, TestCategory("Integration")]
    public async Task A_secret_is_revealed_once_and_only_after_the_user_approves()
    {
        var notices = new ConcurrentBag<KeywardRevealRequestLine>();
        await using var app = await StartAsync(s => s.AddScoped<IKeywardAlertPresenter>(_ => new CapturingPresenter(notices)));
        if (app is null)
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var (tenantId, owner, vault, login, note) = await SeedAsync(app);
        var client = await ClientAsync(app, tenantId, owner, vault, AgentScopes.VaultList | AgentScopes.VaultReveal);

        // Wrong field for the type, unknown field, no reason.
        Assert.AreEqual(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync($"/keyward/api/v1/agent/items/{login}/reveal-requests", new AgentRevealRequestBody("Value", "setup"))).StatusCode);
        Assert.AreEqual(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync($"/keyward/api/v1/agent/items/{login}/reveal-requests", new AgentRevealRequestBody("Secret", "setup"))).StatusCode);
        Assert.AreEqual(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync($"/keyward/api/v1/agent/items/{login}/reveal-requests", new AgentRevealRequestBody("Password", " "))).StatusCode);

        var created = await client.PostAsJsonAsync($"/keyward/api/v1/agent/items/{login}/reveal-requests",
            new AgentRevealRequestBody("Password", "Configure <b>CH-Post</b> client in appsettings"));
        Assert.AreEqual(HttpStatusCode.Accepted, created.StatusCode);
        var request = await created.Content.ReadFromJsonAsync<AgentRevealStateResponse>();
        Assert.AreEqual("Pending", request!.Status);

        // Not before approval.
        var early = await client.PostAsync($"/keyward/api/v1/agent/reveal-requests/{request.Id}/consume", null);
        Assert.AreEqual(HttpStatusCode.Conflict, early.StatusCode);
        Assert.DoesNotContain(Password, await early.Content.ReadAsStringAsync());

        // The user was told — with the reason, without the secret.
        var notice = notices.Single();
        Assert.AreEqual(request.Id, notice.RequestId);
        Assert.AreEqual("Configure <b>CH-Post</b> client in appsettings", notice.Reason);
        Assert.AreEqual(RevealField.Password, notice.Field);

        // The user sees it pending and approves.
        using (var scope = ScopeFor(app.Services, tenantId, owner))
        {
            var reveals = scope.ServiceProvider.GetRequiredService<IRevealRequestService>();
            var pending = (await reveals.ListPendingAsync(owner, tenantId)).Single();
            Assert.AreEqual("CH-Post API", pending.ItemName);
            Assert.AreEqual("Integrations", pending.VaultName);
            await reveals.ApproveAsync(owner, tenantId, request.Id);
            Assert.IsEmpty(await reveals.ListPendingAsync(owner, tenantId));
        }

        Assert.AreEqual("Approved", (await client.GetFromJsonAsync<AgentRevealStateResponse>($"/keyward/api/v1/agent/reveal-requests/{request.Id}"))!.Status);

        // Exactly once.
        var consumed = await client.PostAsync($"/keyward/api/v1/agent/reveal-requests/{request.Id}/consume", null);
        Assert.AreEqual(HttpStatusCode.OK, consumed.StatusCode);
        Assert.IsTrue(consumed.Headers.CacheControl?.NoStore);
        Assert.AreEqual(Password, (await consumed.Content.ReadFromJsonAsync<AgentRevealValueResponse>())!.Value);
        Assert.AreEqual(HttpStatusCode.Conflict, (await client.PostAsync($"/keyward/api/v1/agent/reveal-requests/{request.Id}/consume", null)).StatusCode);
        Assert.AreEqual("Consumed", (await client.GetFromJsonAsync<AgentRevealStateResponse>($"/keyward/api/v1/agent/reveal-requests/{request.Id}"))!.Status);

        // The trail: requested and revealed by the agent, approved by the person.
        using (var scope = ScopeFor(app.Services, tenantId, owner))
        {
            var audit = await scope.ServiceProvider.GetRequiredService<KeywardDbContext>().AuditEntries.AsNoTracking()
                .Where(a => a.TenantId == tenantId && (a.ResourceId == request.Id || a.ResourceId == login))
                .ToListAsync();
            var requested = audit.Single(a => a.Action == AuditAction.RevealRequested);
            Assert.AreEqual(ActorKind.Agent, requested.ActorKind);
            Assert.AreEqual("Configure <b>CH-Post</b> client in appsettings", requested.Reason);
            Assert.AreEqual(ActorKind.User, audit.Single(a => a.Action == AuditAction.RevealApproved).ActorKind);
            var revealed = audit.Single(a => a.Action == AuditAction.Reveal);
            Assert.AreEqual(ActorKind.Agent, revealed.ActorKind);
            Assert.AreEqual("VaultItem", revealed.ResourceType);
        }

        // A non-Login reveals its value; a rejected request reveals nothing.
        var noteRequest = await (await client.PostAsJsonAsync($"/keyward/api/v1/agent/items/{note}/reveal-requests",
            new AgentRevealRequestBody("Value", "check the contract"))).Content.ReadFromJsonAsync<AgentRevealStateResponse>();
        using (var scope = ScopeFor(app.Services, tenantId, owner))
        {
            await scope.ServiceProvider.GetRequiredService<IRevealRequestService>().RejectAsync(owner, tenantId, noteRequest!.Id);
        }

        Assert.AreEqual(HttpStatusCode.Conflict, (await client.PostAsync($"/keyward/api/v1/agent/reveal-requests/{noteRequest!.Id}/consume", null)).StatusCode);
        Assert.AreEqual("Rejected", (await client.GetFromJsonAsync<AgentRevealStateResponse>($"/keyward/api/v1/agent/reveal-requests/{noteRequest.Id}"))!.Status);
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Only_the_token_user_decides_and_access_is_rechecked_at_consume()
    {
        await using var app = await StartAsync();
        if (app is null)
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var (tenantId, owner, vault, login, _) = await SeedAsync(app);

        // Without the reveal scope the item is simply out of reach.
        var listOnly = await ClientAsync(app, tenantId, owner, vault, AgentScopes.VaultList);
        Assert.AreEqual(HttpStatusCode.NotFound, (await listOnly.PostAsJsonAsync($"/keyward/api/v1/agent/items/{login}/reveal-requests", new AgentRevealRequestBody("Password", "x"))).StatusCode);

        var client = await ClientAsync(app, tenantId, owner, vault, AgentScopes.VaultReveal);
        var request = await (await client.PostAsJsonAsync($"/keyward/api/v1/agent/items/{login}/reveal-requests",
            new AgentRevealRequestBody("Password", "deploy"))).Content.ReadFromJsonAsync<AgentRevealStateResponse>();

        // Another member of the tenant cannot decide it.
        var colleague = Guid.NewGuid();
        await AddMemberAsync(app, tenantId, colleague);
        using (var scope = ScopeFor(app.Services, tenantId, colleague))
        {
            await Assert.ThrowsExactlyAsync<UnauthorizedAccessException>(() =>
                scope.ServiceProvider.GetRequiredService<IRevealRequestService>().ApproveAsync(colleague, tenantId, request!.Id));
        }

        // Approved — but the vault is closed to agents before the fetch: nothing is handed out.
        using (var scope = ScopeFor(app.Services, tenantId, owner))
        {
            await scope.ServiceProvider.GetRequiredService<IRevealRequestService>().ApproveAsync(owner, tenantId, request!.Id);
            await scope.ServiceProvider.GetRequiredService<IVaultService>().SetAgentAccessAsync(owner, vault, allowed: false);
        }

        Assert.AreEqual(HttpStatusCode.NotFound, (await client.PostAsync($"/keyward/api/v1/agent/reveal-requests/{request!.Id}/consume", null)).StatusCode);

        // Reopened, the approved request still works once — and a parallel burst yields exactly one value.
        using (var scope = ScopeFor(app.Services, tenantId, owner))
        {
            await scope.ServiceProvider.GetRequiredService<IVaultService>().SetAgentAccessAsync(owner, vault, allowed: true);
        }

        var responses = await Task.WhenAll(Enumerable.Range(0, 5).Select(_ => client.PostAsync($"/keyward/api/v1/agent/reveal-requests/{request.Id}/consume", null)));
        Assert.AreEqual(1, responses.Count(r => r.StatusCode == HttpStatusCode.OK));
        Assert.AreEqual(4, responses.Count(r => r.StatusCode == HttpStatusCode.Conflict));
    }

    [TestMethod, TestCategory("Unit")]
    public void Deadlines_expire_undecided_and_unfetched_requests()
    {
        var created = new DateTimeOffset(2026, 9, 26, 9, 0, 0, TimeSpan.Zero);
        var user = Guid.NewGuid();
        RevealRequest New() => new(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), user, Guid.NewGuid(), RevealField.Password, "why", created);

        var undecided = New();
        Assert.AreEqual(RevealRequestStatus.Pending, undecided.StatusAt(created.AddMinutes(4)));
        Assert.AreEqual(RevealRequestStatus.Expired, undecided.StatusAt(created + RevealRequestLifetime.Pending));
        Assert.ThrowsExactly<InvalidOperationException>(() => undecided.Approve(user, created.AddMinutes(6)));

        var approved = New();
        approved.Approve(user, created.AddMinutes(1));
        Assert.ThrowsExactly<InvalidOperationException>(() => approved.Consume(created.AddMinutes(1) + RevealRequestLifetime.ConsumeWindow));
        Assert.AreEqual(RevealRequestStatus.Expired, approved.StatusAt(created.AddMinutes(3)));

        var fetched = New();
        fetched.Approve(user, created.AddMinutes(1));
        fetched.Consume(created.AddMinutes(1).AddSeconds(30));
        Assert.ThrowsExactly<InvalidOperationException>(() => fetched.Consume(created.AddMinutes(1).AddSeconds(40)));

        Assert.ThrowsExactly<UnauthorizedAccessException>(() => New().Approve(Guid.NewGuid(), created));
        Assert.ThrowsExactly<ArgumentException>(() =>
            new RevealRequest(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), user, Guid.NewGuid(), RevealField.Value, new string('x', RevealRequest.MaxReasonLength + 1), created));
    }

    private static async Task<(Guid TenantId, Guid Owner, Guid Vault, Guid Login, Guid Note)> SeedAsync(WebApplication app)
    {
        var tenantId = Guid.NewGuid();
        var owner = Guid.NewGuid();
        await SeedTenantAsync(app.Services, tenantId, owner);

        using var scope = ScopeFor(app.Services, tenantId, owner);
        var vaults = scope.ServiceProvider.GetRequiredService<IVaultService>();
        var vault = await vaults.CreateTenantVaultAsync(new CreateTenantVaultCommand(owner, tenantId, "Integrations"));
        await vaults.SetAgentAccessAsync(owner, vault, allowed: true);
        var login = await vaults.AddItemAsync(new AddVaultItemCommand(owner, vault, null, ItemType.Login, "CH-Post API",
            LoginContent.ToJson("https://api.post.ch", "bvd-client", Password, "")));
        var note = await vaults.AddItemAsync(new AddVaultItemCommand(owner, vault, null, ItemType.SecureNote, "Contract", "contract-text"));
        return (tenantId, owner, vault, login, note);
    }

    private static async Task<HttpClient> ClientAsync(WebApplication app, Guid tenantId, Guid userId, Guid vault, AgentScopes scopes)
    {
        var client = app.GetTestClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", await IssueAsync(app.Services, tenantId, userId, vault, scopes));
        return client;
    }

    private static async Task AddMemberAsync(WebApplication app, Guid tenantId, Guid userId)
    {
        using var scope = app.Services.CreateScope();
        scope.ServiceProvider.GetRequiredService<Am.Keyward.Core.Abstractions.ITenantScopeSetter>().SetTenant(tenantId);
        var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
        db.Users.Add(new Am.Keyward.Core.Domain.Identity.AppUser(userId, null, $"user-{userId:N}", "colleague", false, DateTimeOffset.UtcNow));
        db.TenantMemberships.Add(new Am.Keyward.Core.Domain.Identity.TenantMembership(Guid.NewGuid(), tenantId, userId, TenantRole.Member, DateTimeOffset.UtcNow));
        await db.SaveChangesAsync();
    }

    private sealed class CapturingPresenter(ConcurrentBag<KeywardRevealRequestLine> notices) : IKeywardAlertPresenter
    {
        public Task<int> NotifyTokenAlertsAsync(Guid tenantId, bool monitoring, IReadOnlyList<KeywardAlertRecipient> recipients, IReadOnlyList<KeywardTokenAlertLine> lines, CancellationToken ct = default) => Task.FromResult(0);

        public Task<int> NotifyTokenExpiryAsync(Guid tenantId, IReadOnlyList<KeywardAlertRecipient> recipients, IReadOnlyList<KeywardTokenExpiryLine> lines, CancellationToken ct = default) => Task.FromResult(0);

        public Task<int> NotifySecretExpiryAsync(Guid tenantId, IReadOnlyList<KeywardAlertRecipient> recipients, IReadOnlyList<KeywardSecretExpiryLine> lines, CancellationToken ct = default) => Task.FromResult(0);

        public Task<int> NotifyRevealRequestAsync(Guid tenantId, KeywardAlertRecipient recipient, KeywardRevealRequestLine line, CancellationToken ct = default)
        {
            notices.Add(line);
            return Task.FromResult(1);
        }
    }
}
