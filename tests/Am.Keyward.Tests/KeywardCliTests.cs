using System.Diagnostics;
using System.Security.Cryptography;
using Am.Keyward.Api;
using Am.Keyward.Cli;
using Am.Keyward.Client;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Agent;
using Am.Keyward.Core.Domain.Identity;
using Am.Keyward.Infrastructure;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

namespace Am.Keyward.Tests;

/// <summary>
/// The `keyward` command line (decisions T18–T23, T30, 2026-10-13): app-token profiles, reads with one exit code per
/// cause, `run` / `headers` / `env`, per-read audit for script tokens, and `import` of a plain-text file through the
/// agent API with nothing guessed.
/// </summary>
[TestClass]
public class KeywardCliTests
{
    private static readonly Uri Service = new("https://keyward.test");

    // --- without a database ---

    [TestMethod, TestCategory("Unit")]
    public void A_reference_is_profile_then_key_and_the_key_may_hold_colons()
    {
        var reference = SecretReference.Parse("ops:Prtg:ApiToken");
        Assert.AreEqual("ops", reference.Profile);
        Assert.AreEqual("Prtg:ApiToken", reference.Key);
        Assert.AreEqual(2, (int)Assert.ThrowsExactly<KeywardCliException>(() => SecretReference.Parse("no-colon")).Code);
        Assert.AreEqual("P_Prtg__ApiToken", SecretReference.VariableNameFor("Prtg:ApiToken", "P_"));
        Assert.AreEqual("Mail_Relay__Key", SecretReference.VariableNameFor("Mail-Relay:Key"));
    }

    [TestMethod, TestCategory("Unit")]
    public void Import_takes_exactly_one_line_per_entry_and_never_guesses()
    {
        string[] source =
        [
            "# Monitoring",
            "PRTG API token: `abc123`",
            "PRTG user: `monitor`",
            "Mail relay key: `k1`",
            "Mail relay key (old): `k0`",
        ];

        var good = SecretImport.Plan("""
            { "entries": [ { "pattern": "^PRTG API token: `(?<value>[^`]+)`$", "application": "Ops.Prtg", "environment": "Production", "key": "Prtg:ApiToken" } ] }
            """, source);
        Assert.IsEmpty(good.Problems);
        Assert.AreEqual(new ImportRow(2, "Ops.Prtg", "Production", "Prtg:ApiToken", "abc123"), good.Rows.Single());

        var bad = SecretImport.Plan("""
            { "entries": [
              { "pattern": "^Mail relay key", "application": "Ops", "environment": "Production", "key": "Relay:Key" },
              { "pattern": "^nothing here", "application": "Ops", "environment": "Production", "key": "A" },
              { "pattern": "^PRTG user: ", "application": "Ops", "environment": "Production", "key": "B" },
              { "pattern": "(", "application": "Ops", "environment": "Production", "key": "C" }
            ] }
            """, source);
        Assert.HasCount(4, bad.Problems);
        StringAssert.Contains(bad.Problems[0], "matches 2 lines (4, 5)");
        StringAssert.Contains(bad.Problems[1], "matches no line");
        StringAssert.Contains(bad.Problems[2], "captures no value");
        StringAssert.Contains(bad.Problems[3], "not a valid regular expression");
        Assert.IsEmpty(bad.Rows.Where(r => r.Key == "Relay:Key"));

        Assert.IsNotEmpty(SecretImport.Plan("not json", source).Problems);
    }

    [TestMethod, TestCategory("Unit")]
    public async Task Usage_errors_and_unknown_profiles_have_their_own_exit_codes()
    {
        var (cli, _, err) = Cli(new KeywardProfiles(TempFile(), _ => new MemoryStore(), _ => null), app: null);
        Assert.AreEqual(2, await cli.RunAsync(["nonsense"]));
        Assert.AreEqual(2, await cli.RunAsync(["get", "ops:Key", "--unknown-flag"]));
        Assert.AreEqual(3, await cli.RunAsync(["get", "ops:Key"]));
        StringAssert.Contains(err.ToString(), "keyward login ops");
    }

    [TestMethod, TestCategory("Unit")]
    public void The_PowerShell_vault_installs_with_a_plain_module_version()
    {
        var folder = Path.Combine(Path.GetTempPath(), $"kw-ps-{Guid.NewGuid():N}");
        try
        {
            var target = PowerShellModule.Install(folder);
            var manifest = File.ReadAllText(Path.Combine(target, "Am.Keyward.SecretManagement.psd1"));
            Assert.DoesNotContain("{{VERSION}}", manifest);
            Assert.IsTrue(File.Exists(Path.Combine(target, "Am.Keyward.SecretManagement.Extension", "Am.Keyward.SecretManagement.Extension.psm1")));
            Assert.IsTrue(File.Exists(Path.Combine(target, "Am.Keyward.SecretManagement.Extension", "Invoke-Keyward.ps1")));
        }
        finally
        {
            Directory.Delete(folder, recursive: true);
        }
    }

    // --- against a real server ---

    [TestMethod, TestCategory("Integration")]
    public async Task A_script_reads_through_its_app_token_with_a_clear_reason_when_it_cannot()
    {
        await using var app = await StartAsync();
        if (app is null)
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var seed = await SeedAsync(app.Services);
        var store = new MemoryStore();
        var profiles = new KeywardProfiles(TempFile(), _ => store, _ => null);

        // login: an agent token is refused, the app token is checked and stored.
        var (cli, output, err) = Cli(profiles, app, input: "amkwa_aaaaaaaaaaaa_bbbb");
        Assert.AreEqual(2, await cli.RunAsync(["login", "ops", "--service", Service.ToString(), "--token-stdin"]));
        (cli, output, err) = Cli(profiles, app, input: seed.AppToken);
        Assert.AreEqual(0, await cli.RunAsync(["login", "ops", "--service", Service.ToString(), "--token-stdin"]), err.ToString());
        Assert.AreEqual(seed.AppToken, store.Read());

        (cli, output, err) = Cli(profiles, app);
        Assert.AreEqual(0, await cli.RunAsync(["get", "ops:Prtg:Token"]), err.ToString());
        Assert.AreEqual("tok-123", output.ToString().Trim());

        (cli, output, _) = Cli(profiles, app);
        Assert.AreEqual(0, await cli.RunAsync(["keys", "ops", "--json"]));
        StringAssert.Contains(output.ToString(), "Prtg:Password");

        // One exit code per cause.
        (cli, _, err) = Cli(profiles, app);
        Assert.AreEqual(6, await cli.RunAsync(["get", "ops:No:Such"]));
        StringAssert.Contains(err.ToString(), "no key 'No:Such'");
        Assert.AreEqual(7, await Cli(profiles, app).Cli.RunAsync(["get", "ops:Only:InTest"]));

        // headers for Claude Code's headersHelper; run gives the values to the child only.
        (cli, output, _) = Cli(profiles, app);
        Assert.AreEqual(0, await cli.RunAsync(["headers", "--set", "Authorization=Bearer {ops:Prtg:Token}"]));
        Assert.AreEqual("""{"Authorization":"Bearer tok-123"}""", output.ToString().Trim());

        ProcessStartInfo? started = null;
        (cli, _, _) = Cli(profiles, app, run: start => { started = start; return 0; });
        Assert.AreEqual(0, await cli.RunAsync(["run", "--env", "PRTG_TOKEN=ops:Prtg:Token", "--all", "ops", "--prefix", "KW_", "--", "monitor.exe", "--check", "a b"]));
        Assert.AreEqual("tok-123", started!.Environment["PRTG_TOKEN"]);
        Assert.AreEqual("pw-456", started.Environment["KW_Prtg__Password"]);
        CollectionAssert.AreEqual(new[] { "--check", "a b" }, started.ArgumentList.ToArray());

        (cli, output, _) = Cli(profiles, app);
        Assert.AreEqual(0, await cli.RunAsync(["env", "ops", "--shell", "powershell"]));
        StringAssert.Contains(output.ToString(), "$env:Prtg__Token = 'tok-123'");

        // The script token audits every single read (T23 A): get, headers and run --env — three; bulk reads (keys,
        // --all, env) are audited as one entry without a resource id, as for every token.
        using (var scope = AgentApiTests.ScopeFor(app.Services, seed.TenantId, seed.Manager))
        {
            var reads = await scope.ServiceProvider.GetRequiredService<KeywardDbContext>().AuditEntries.AsNoTracking()
                .CountAsync(a => a.TenantId == seed.TenantId && a.ResourceType == "SoftwareSecret" && a.Action == AuditAction.Read
                    && a.ActorKind == ActorKind.SoftwareClient && a.ResourceId != null);
            Assert.AreEqual(3, reads);

            await scope.ServiceProvider.GetRequiredService<ISoftwareClientTokenService>().RevokeAsync(seed.TenantId, seed.AppTokenId, seed.Manager);
        }

        (cli, _, err) = Cli(profiles, app);
        Assert.AreEqual(4, await cli.RunAsync(["get", "ops:Prtg:Token"]));
        StringAssert.Contains(err.ToString(), "keyward login ops");
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Import_writes_mapped_values_through_the_agent_API_and_keeps_existing_ones()
    {
        await using var app = await StartAsync();
        if (app is null)
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var seed = await SeedAsync(app.Services);
        var folder = Path.Combine(Path.GetTempPath(), $"kw-import-{Guid.NewGuid():N}");
        Directory.CreateDirectory(folder);
        var source = Path.Combine(folder, "secrets.md");
        var mapping = Path.Combine(folder, "map.json");
        File.WriteAllLines(source, ["Relay key: `relay-1`", "PRTG token: `tok-new`"]);
        File.WriteAllText(mapping, """
            { "entries": [
              { "pattern": "^Relay key: `(?<value>[^`]+)`$", "application": "Ops.Prtg", "environment": "Production", "key": "Relay:Key" },
              { "pattern": "^PRTG token: `(?<value>[^`]+)`$", "application": "Ops.Prtg", "environment": "Production", "key": "Prtg:Token" }
            ] }
            """);

        var profiles = new KeywardProfiles(TempFile(), _ => new MemoryStore(), _ => null);
        var (cli, output, err) = Cli(profiles, app, agentToken: seed.AgentToken);
        Assert.AreEqual(0, await cli.RunAsync(["import", "--service", Service.ToString(), "--mapping", mapping, "--source", source, "--dry-run"]), err.ToString());
        Assert.DoesNotContain("relay-1", output.ToString(), "a dry run never prints a value");

        (cli, output, err) = Cli(profiles, app, agentToken: seed.AgentToken);
        Assert.AreEqual(0, await cli.RunAsync(["import", "--service", Service.ToString(), "--mapping", mapping, "--source", source]), err.ToString());
        StringAssert.Contains(output.ToString(), "Relay:Key - created");
        StringAssert.Contains(output.ToString(), "Prtg:Token - already has a value, skipped");
        Assert.DoesNotContain("relay-1", output.ToString() + err.ToString());

        using var scope = AgentApiTests.ScopeFor(app.Services, seed.TenantId, seed.Manager);
        var secrets = scope.ServiceProvider.GetRequiredService<ISoftwareSecretService>();
        Assert.AreEqual("relay-1", await secrets.ReadAsync(new ReadSoftwareSecretQuery(seed.TenantId, seed.ProjectId, "Production", "Relay:Key", seed.Manager)));
        Assert.AreEqual("tok-123", await secrets.ReadAsync(new ReadSoftwareSecretQuery(seed.TenantId, seed.ProjectId, "Production", "Prtg:Token", seed.Manager)));
        Directory.Delete(folder, recursive: true);
    }

    // --- helpers ---

    private static (KeywardCli Cli, StringWriter Out, StringWriter Err) Cli(
        KeywardProfiles profiles, WebApplication? app, string input = "", string? agentToken = null, Func<ProcessStartInfo, int>? run = null)
    {
        var output = new StringWriter();
        var err = new StringWriter();
        var context = new KeywardCliContext
        {
            Out = output,
            Err = err,
            In = new StringReader(input),
            Profiles = profiles,
            HttpClientFor = (service, token, _) =>
            {
                var client = app?.GetTestClient() ?? throw new InvalidOperationException("No server in this test.");
                client.BaseAddress = new Uri(service.GetLeftPart(UriPartial.Authority) + "/");
                client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
                return client;
            },
            ReadHiddenToken = () => throw new InvalidOperationException("No console in a test."),
            InputRedirected = true,
            AgentTokenFor = _ => agentToken,
            RunProcess = start => Task.FromResult(run?.Invoke(start) ?? 0),
            PowerShellModulesFolder = _ => Path.GetTempPath(),
        };
        return (new KeywardCli(context), output, err);
    }

    private static string TempFile() => Path.Combine(Path.GetTempPath(), $"kw-profiles-{Guid.NewGuid():N}.json");

    private static async Task<WebApplication?> StartAsync()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddKeyward(TestConfig.ConnectionString, RandomNumberGenerator.GetBytes(32), "test-kek:v1");
        builder.Services.AddKeywardSoftwareClientApi();
        builder.Services.AddKeywardAgentApi();
        builder.Services.RemoveAll<IHostedService>();

        var app = builder.Build();
        app.UseRateLimiter();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapKeywardClientApi();
        app.MapKeywardAgentApi();

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

    private sealed record Seed(Guid TenantId, Guid Manager, Guid ProjectId, string AppToken, Guid AppTokenId, string AgentToken);

    // A software manager, application «Ops.Prtg» with two Production values and a key that is only set in Test,
    // a Production app token that audits every read, and an agent token that may manage the application.
    private static async Task<Seed> SeedAsync(IServiceProvider services)
    {
        var tenantId = Guid.NewGuid();
        var manager = Guid.NewGuid();
        using (var seed = services.CreateScope())
        {
            seed.ServiceProvider.GetRequiredService<ITenantScopeSetter>().SetTenant(tenantId);
            var db = seed.ServiceProvider.GetRequiredService<KeywardDbContext>();
            db.Tenants.Add(new Tenant(tenantId, "keyward-cli-test", isSystemTenant: false, DateTimeOffset.UtcNow));
            var user = new AppUser(manager, issuer: null, externalId: $"user-{manager:N}", displayName: "manager", isSystemAdmin: false, DateTimeOffset.UtcNow);
            user.GrantSoftwareManager();
            db.Users.Add(user);
            db.TenantMemberships.Add(new TenantMembership(Guid.NewGuid(), tenantId, manager, TenantRole.Member, DateTimeOffset.UtcNow));
            await db.SaveChangesAsync();
        }

        using var scope = AgentApiTests.ScopeFor(services, tenantId, manager);
        var projectId = await scope.ServiceProvider.GetRequiredService<IProjectService>().CreateAsync(tenantId, "Ops.Prtg", manager);
        var secrets = scope.ServiceProvider.GetRequiredService<ISoftwareSecretService>();
        await secrets.StoreAsync(new StoreSoftwareSecretCommand(tenantId, projectId, "Production", "Prtg:Token", "tok-123", manager));
        await secrets.StoreAsync(new StoreSoftwareSecretCommand(tenantId, projectId, "Production", "Prtg:Password", "pw-456", manager));
        await secrets.StoreAsync(new StoreSoftwareSecretCommand(tenantId, projectId, "Test", "Only:InTest", "t", manager));

        var app = await scope.ServiceProvider.GetRequiredService<ISoftwareClientTokenService>().IssueAsync(
            new IssueSoftwareClientTokenCommand(tenantId, projectId, "Production", $"cli-{Guid.NewGuid():N}", null, manager, AuditReads: true));
        var agent = await scope.ServiceProvider.GetRequiredService<IAgentTokenService>().IssueAsync(new IssueAgentTokenCommand(
            manager, tenantId, $"agent-{Guid.NewGuid():N}", AgentScopes.ManageApplications, [], ApplicationIds: [projectId]));
        return new Seed(tenantId, manager, projectId, app.Token, app.TokenId, agent.Token);
    }

    private sealed class MemoryStore : IKeywardCredentialStore
    {
        private string? value;

        public string Place => "memory";

        public string? Read() => value;

        public void Write(string token) => value = token;

        public bool Delete()
        {
            var had = value is not null;
            value = null;
            return had;
        }
    }
}
