using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using Am.Keyward.Api;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Identity;
using Am.Keyward.Core.Domain.Software;
using Am.Keyward.Core.Domain.ValueObjects;
using Am.Keyward.Infrastructure;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Am.Keyward.Tests;

/// <summary>
/// The host-wide network restriction of the software-client API (<c>Keyward:Client:AllowedNetworks</c>): only the
/// configured networks reach the token check; everyone else gets 403 with an empty body. Without the setting the API
/// stays open (backward compatible) and the startup log warns; an unusable setting refuses everyone and never stops
/// the host.
/// </summary>
[TestClass]
public class SoftwareClientNetworkPolicyTests
{
    private const string Lan = "10.1.0.0/23";
    private const string TestClientIpHeader = AgentApiTests.TestClientIpHeader;
    private static readonly string BogusToken = "amkw_000000000000_" + new string('0', 64);

    [TestMethod, TestCategory("Integration")]
    public async Task Only_the_allowed_networks_reach_the_client_api()
    {
        await using var app = await StartAsync(o => o.AllowedNetworks = Lan);
        if (app is null)
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var token = await SeedApplicationWithTokenAsync(app.Services);

        Assert.AreEqual(HttpStatusCode.OK, await GetSecretsFrom(app, "10.1.0.26", token), "A LAN client with a valid token.");
        Assert.AreEqual(HttpStatusCode.OK, await GetSecretsFrom(app, "::ffff:10.1.1.112", token), "IPv4-mapped IPv6 from the LAN.");
        Assert.AreEqual(HttpStatusCode.Forbidden, await GetSecretsFrom(app, "172.16.0.93", token), "Through the reverse proxy — i.e. from the internet.");
        Assert.AreEqual(HttpStatusCode.Forbidden, await GetSecretsFrom(app, "10.1.2.1", token), "Just outside the LAN range.");
        Assert.AreEqual(HttpStatusCode.Forbidden, await GetSecretsFrom(app, null, token), "Unknown client address.");

        // From outside it is a network matter (403), whatever the request carries — no token is looked up.
        Assert.AreEqual(HttpStatusCode.Forbidden, await GetSecretsFrom(app, "172.16.0.93", BogusToken));
        Assert.AreEqual(HttpStatusCode.Forbidden, await GetSecretsFrom(app, "172.16.0.93", bearer: null), "No header from outside.");
        Assert.AreEqual(HttpStatusCode.Unauthorized, await GetSecretsFrom(app, "10.1.0.26", BogusToken), "Inside, a bad token stays 401.");

        var refused = await SendFrom(app, "/keyward/api/v1/ping", "8.8.8.8", token);
        Assert.AreEqual(HttpStatusCode.Forbidden, refused.StatusCode);
        Assert.AreEqual(string.Empty, await refused.Content.ReadAsStringAsync(), "403 with an empty body.");
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Without_the_setting_the_client_api_stays_open_to_every_network()
    {
        await using var app = await StartAsync(configure: null);
        if (app is null)
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var token = await SeedApplicationWithTokenAsync(app.Services);

        Assert.AreEqual(HttpStatusCode.OK, await GetSecretsFrom(app, "8.8.8.8", token), "Backward compatible: no setting, no restriction.");
    }

    [TestMethod, TestCategory("Integration")]
    public async Task A_malformed_setting_refuses_everyone_instead_of_stopping_the_host()
    {
        // A bare address without a prefix — the typo the startup used to die on (on the agent API).
        await using var app = await StartAsync(o => o.AllowedNetworks = "10.1.0.0/23, 10.1.0.5");
        if (app is null)
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var token = await SeedApplicationWithTokenAsync(app.Services);

        Assert.AreEqual(HttpStatusCode.Forbidden, await GetSecretsFrom(app, "10.1.0.26", token), "Fail closed: even the LAN is refused.");
        Assert.IsFalse(app.Services.GetRequiredService<SoftwareClientNetworkPolicy>().IsValid);
    }

    [TestMethod, TestCategory("Unit")]
    public void Policy_parses_the_client_setting_and_names_the_client_api_in_errors()
    {
        var policy = SoftwareClientNetworkPolicy.Parse("10.1.0.0/23; 192.168.10.0/24");
        Assert.IsTrue(policy.IsValid);
        Assert.IsTrue(policy.IsRestricted);
        Assert.IsTrue(policy.Allows(IPAddress.Parse("192.168.10.5")));
        Assert.IsTrue(policy.Allows(IPAddress.Parse("::ffff:10.1.1.1")));
        Assert.IsFalse(policy.Allows(IPAddress.Parse("192.168.11.5")));
        Assert.IsFalse(policy.Allows(null));

        var open = SoftwareClientNetworkPolicy.Parse(null);
        Assert.IsTrue(open.IsValid);
        Assert.IsFalse(open.IsRestricted);
        Assert.IsTrue(open.Allows(IPAddress.Parse("8.8.8.8")));

        var broken = SoftwareClientNetworkPolicy.Parse("10.1.0.0/23, lan");
        Assert.IsFalse(broken.IsValid);
        Assert.IsTrue(broken.IsRestricted);
        Assert.IsFalse(broken.Allows(IPAddress.Parse("10.1.0.26")), "An unusable setting refuses everyone.");
        StringAssert.Contains(broken.Error, "software-client API");
        StringAssert.Contains(broken.Error, KeywardSoftwareClientApiOptions.AllowedNetworksConfigurationKey);
        Assert.IsFalse(broken.Error!.Contains("agent", StringComparison.OrdinalIgnoreCase), "The client setting's error must not speak of the agent API.");

        Assert.IsFalse(SoftwareClientNetworkPolicy.Parse(" , ;").IsValid, "Only separators is a broken value, not 'no restriction'.");
        Assert.IsFalse(SoftwareClientNetworkPolicy.Parse("10.1.0.5").IsValid, "A bare address without a prefix.");
        Assert.IsFalse(SoftwareClientNetworkPolicy.Parse("10.1.0.0/33").IsValid, "Prefix out of range.");
    }

    [TestMethod, TestCategory("Unit")]
    public void A_setting_that_contains_a_known_reverse_proxy_is_rejected()
    {
        var proxies = new[] { IPAddress.Parse("172.16.0.93") };

        var admitsProxy = SoftwareClientNetworkPolicy.Parse("10.1.0.0/23, 172.16.0.0/24", proxies);
        Assert.IsFalse(admitsProxy.IsValid);
        StringAssert.Contains(admitsProxy.Error, "172.16.0.93");
        Assert.IsFalse(admitsProxy.Allows(IPAddress.Parse("10.1.0.26")), "Fail closed.");

        Assert.IsTrue(SoftwareClientNetworkPolicy.Parse(Lan, proxies).IsValid);
        Assert.IsFalse(AgentNetworkPolicy.Parse("172.16.0.0/16", [IPAddress.Parse("::ffff:172.16.0.93")]).IsValid, "IPv4-mapped proxy address.");
    }

    [TestMethod, TestCategory("Unit")]
    public async Task Startup_log_warns_without_a_setting_and_reports_a_malformed_one_as_an_error()
    {
        Assert.AreEqual(
            LogLevel.Warning,
            (await StartupLogAsync(client: o => o.AllowedNetworks = null)).Single(e => e.Message.Contains(KeywardSoftwareClientApiOptions.AllowedNetworksConfigurationKey)).Level);

        var malformedClient = (await StartupLogAsync(client: o => o.AllowedNetworks = "10.1.0.5")).Single(e => e.Level == LogLevel.Error);
        StringAssert.Contains(malformedClient.Message, "software-client API");

        var malformedAgent = (await StartupLogAsync(client: o => o.AllowedNetworks = Lan, agent: o => o.AllowedNetworks = "10.1.0.0/23, lan"))
            .Single(e => e.Level == LogLevel.Error);
        StringAssert.Contains(malformedAgent.Message, "agent API");

        Assert.IsEmpty(
            (await StartupLogAsync(client: o => o.AllowedNetworks = Lan, agent: o => o.AllowedNetworks = Lan)).Where(e => e.Level >= LogLevel.Warning),
            "Valid settings log nothing.");
    }

    // The production pipeline order: rate limiter before authentication, then authorization, then endpoints.
    private static async Task<WebApplication?> StartAsync(Action<KeywardSoftwareClientApiOptions>? configure)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddKeyward(TestConfig.ConnectionString, RandomNumberGenerator.GetBytes(32), "test-kek:v1");
        builder.Services.AddKeywardSoftwareClientApi(configure);

        // Endpoints only: Keyward's background services must not run against the shared test database.
        builder.Services.RemoveAll<IHostedService>();

        var app = builder.Build();
        app.Use((context, next) =>
        {
            if (context.Request.Headers.TryGetValue(TestClientIpHeader, out var ip))
            {
                context.Connection.RemoteIpAddress = IPAddress.Parse(ip.ToString());
            }

            return next();
        });
        app.UseRateLimiter();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapKeywardClientApi();

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

    /// <summary>A tenant with one application, a value in Production and a Production app token — seeded as the system.</summary>
    private static async Task<string> SeedApplicationWithTokenAsync(IServiceProvider services)
    {
        var tenantId = Guid.NewGuid();
        var projectId = Guid.NewGuid();
        using var scope = services.CreateScope();
        scope.ServiceProvider.GetRequiredService<ITenantScopeSetter>().SetTenant(tenantId);
        scope.ServiceProvider.GetRequiredService<IActorScopeSetter>().SetSystemActor();

        var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
        db.Tenants.Add(new Tenant(tenantId, "client-network-test", isSystemTenant: false, DateTimeOffset.UtcNow));
        var project = new Project(projectId, tenantId, OwnerType.Tenant, tenantId, "client-network", DateTimeOffset.UtcNow);
        project.AddEnvironment(Guid.NewGuid(), Core.Domain.ValueObjects.EnvironmentName.Production, DateTimeOffset.UtcNow);
        db.Projects.Add(project);
        await db.SaveChangesAsync();

        await scope.ServiceProvider.GetRequiredService<ISoftwareSecretService>()
            .StoreAsync(new StoreSoftwareSecretCommand(tenantId, projectId, "Production", "Db:Password", "s3cret", null));
        var issued = await scope.ServiceProvider.GetRequiredService<ISoftwareClientTokenService>()
            .IssueAsync(new IssueSoftwareClientTokenCommand(tenantId, projectId, "Production", $"token {Guid.NewGuid():N}", null, null));
        return issued.Token;
    }

    private static async Task<HttpStatusCode> GetSecretsFrom(WebApplication app, string? ip, string? bearer) =>
        (await SendFrom(app, "/keyward/api/v1/secrets", ip, bearer)).StatusCode;

    private static Task<HttpResponseMessage> SendFrom(WebApplication app, string path, string? ip, string? bearer)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, path);
        if (bearer is not null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        }

        if (ip is not null)
        {
            request.Headers.Add(TestClientIpHeader, ip);
        }

        return app.GetTestClient().SendAsync(request);
    }

    /// <summary>Runs only the network-policy startup reports of a host that registers both APIs, and returns what they logged.</summary>
    private static async Task<IReadOnlyList<(LogLevel Level, string Message)>> StartupLogAsync(
        Action<KeywardSoftwareClientApiOptions> client, Action<KeywardAgentApiOptions>? agent = null)
    {
        var sink = new CapturingLoggerProvider();
        var services = new ServiceCollection();
        services.AddLogging(logging => logging.AddProvider(sink));
        services.AddKeywardSoftwareClientApi(client);
        services.AddKeywardAgentApi(agent);

        await using var provider = services.BuildServiceProvider();
        foreach (var hosted in provider.GetServices<IHostedService>())
        {
            await hosted.StartAsync(CancellationToken.None);
        }

        return [.. sink.Entries];
    }

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        public ConcurrentQueue<(LogLevel Level, string Message)> Entries { get; } = new();

        public ILogger CreateLogger(string categoryName) => new CapturingLogger(Entries);

        public void Dispose()
        {
        }

        private sealed class CapturingLogger(ConcurrentQueue<(LogLevel Level, string Message)> entries) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state)
                where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
                entries.Enqueue((logLevel, formatter(state, exception)));
        }
    }
}
