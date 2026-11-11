using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Am.Keyward.Core.Application;
using Am.Keyward.Ui.Blazor;
using Am.Keyward.Ui.Blazor.App;
using Am.Keyward.Ui.Blazor.App.Hosting;
using Am.Keyward.Ui.Blazor.App.Identity;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Am.Keyward.Tests;

/// <summary>
/// Review 3, reference shell: the pure startup rules (environment, connection string, public base URL, key custody,
/// proxies), the return-URL check and the account-link builder — without a host.
/// </summary>
[TestClass]
public class Review3ShellUnitTests
{
    [TestMethod, TestCategory("Shell")]
    [DataRow("/", true)]
    [DataRow("/amkeyward/vaults?x=1", true)]
    [DataRow("//evil.example", false)]
    [DataRow("/\\evil.example", false)]
    [DataRow("https://evil.example/", false)]
    [DataRow("javascript:alert(1)", false)]
    [DataRow("evil.example", false)]
    [DataRow("/ok\r\nSet-Cookie: x", false)]
    [DataRow("", false)]
    [DataRow(null, false)]
    public void Only_paths_on_this_site_are_followed_after_sign_in(string? url, bool local)
    {
        Assert.AreEqual(local, LocalUrl.IsLocal(url));
        Assert.AreEqual(local ? url : "/", LocalUrl.OrRoot(url));
    }

    [TestMethod, TestCategory("Shell")]
    public void An_unset_environment_refuses_to_start()
    {
        var errors = ShellStartupValidation.Validate(Config(), explicitEnvironment: null, isDevelopment: false);

        Assert.HasCount(1, errors);
        StringAssert.Contains(errors[0], "ASPNETCORE_ENVIRONMENT");
    }

    [TestMethod, TestCategory("Shell")]
    public void Development_needs_no_connection_string_or_public_base_url()
    {
        Assert.IsEmpty(ShellStartupValidation.Validate(Config(), "Development", isDevelopment: true));
    }

    [TestMethod, TestCategory("Shell")]
    public void Outside_development_the_connection_string_and_an_https_public_base_url_are_required()
    {
        var missing = ShellStartupValidation.Validate(Config(), "Production", isDevelopment: false);
        Assert.HasCount(2, missing);
        Assert.IsTrue(missing.Any(e => e.Contains("ConnectionStrings:Keyward", StringComparison.Ordinal)));
        Assert.IsTrue(missing.Any(e => e.Contains(ShellStartupValidation.PublicBaseUrlKey, StringComparison.Ordinal)));

        var http = ShellStartupValidation.Validate(
            Config(("ConnectionStrings:Keyward", "Server=x"), (ShellStartupValidation.PublicBaseUrlKey, "http://keyward.example.test")),
            "Production", isDevelopment: false);
        Assert.HasCount(1, http);

        Assert.IsEmpty(ShellStartupValidation.Validate(
            Config(("ConnectionStrings:Keyward", "Server=x"), (ShellStartupValidation.PublicBaseUrlKey, "https://keyward.example.test")),
            "Production", isDevelopment: false));
    }

    [TestMethod, TestCategory("Shell")]
    public void A_mistyped_registration_mode_or_proxy_refuses_to_start()
    {
        var errors = ShellStartupValidation.Validate(
            Config(
                (RegistrationOptions.ModeKey, "Opne"),
                (ShellForwardedHeaders.KnownProxiesKey, "10.0.0.1, proxy.local"),
                (ShellForwardedHeaders.KnownNetworksKey, "10.0.0.0/33")),
            "Development", isDevelopment: true);

        Assert.HasCount(3, errors);
        Assert.IsEmpty(ShellStartupValidation.Validate(Config((RegistrationOptions.ModeKey, "open")), "Development", true));
    }

    [TestMethod, TestCategory("Shell")]
    public void Development_uses_the_dev_key_with_a_fingerprinted_id()
    {
        var contentRoot = NewDirectory();
        try
        {
            var (kek, error) = ShellKek.Load(Config(), contentRoot, isDevelopment: true);

            Assert.IsNull(error);
            Assert.IsNotNull(kek);
            Assert.StartsWith(DevKek.FormatId + ":", kek.KekId);
            Assert.IsTrue(File.Exists(Path.Combine(contentRoot, DevKek.FileName)));
        }
        finally
        {
            Directory.Delete(contentRoot, recursive: true);
        }
    }

    [TestMethod, TestCategory("Shell")]
    public void Outside_development_the_key_lives_in_a_dpapi_file_never_in_the_content_root()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Inconclusive("DPAPI is Windows-only.");
            return;
        }

        var contentRoot = NewDirectory();
        var kekDirectory = NewDirectory();
        try
        {
            var (kek, error) = ShellKek.Load(Config((ShellKek.DirectoryKey, kekDirectory)), contentRoot, isDevelopment: false);

            Assert.IsNull(error);
            Assert.IsNotNull(kek);
            Assert.StartsWith("dpapi-file:v1:", kek.KekId);
            Assert.IsTrue(kek.Created);
            Assert.IsFalse(File.Exists(Path.Combine(contentRoot, DevKek.FileName)));

            // A dev key next to a non-development start means the data was written with it: refuse.
            File.WriteAllText(Path.Combine(contentRoot, DevKek.FileName), Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));
            var (refused, refusal) = ShellKek.Load(Config((ShellKek.DirectoryKey, kekDirectory)), contentRoot, isDevelopment: false);
            Assert.IsNull(refused);
            StringAssert.Contains(refusal, DevKek.FileName);
        }
        finally
        {
            Directory.Delete(contentRoot, recursive: true);
            Directory.Delete(kekDirectory, recursive: true);
        }
    }

    [TestMethod, TestCategory("Shell")]
    public void Account_links_come_from_the_public_base_url_never_from_the_request_host()
    {
        var production = new AccountLinkBuilder(new KeywardUiOptions { PublicBaseUrl = "https://keyward.example.test/" }, new FakeEnvironment("Production"));
        var link = production.Build("account/reset-password", new Dictionary<string, string?> { ["email"] = "a@b.c", ["token"] = "t" }, "https://attacker.example/");
        Assert.AreEqual("https://keyward.example.test/account/reset-password?email=a@b.c&token=t", link);

        var unconfigured = new AccountLinkBuilder(new KeywardUiOptions(), new FakeEnvironment("Production"));
        Assert.ThrowsExactly<InvalidOperationException>(() =>
            unconfigured.Build("account/reset-password", new Dictionary<string, string?>(), "https://attacker.example/"));

        var development = new AccountLinkBuilder(new KeywardUiOptions(), new FakeEnvironment("Development"));
        StringAssert.StartsWith(
            development.Build("account/confirm-email", new Dictionary<string, string?>(), "https://localhost:7212/"),
            "https://localhost:7212/account/confirm-email");
    }

    private static IConfiguration Config(params (string Key, string? Value)[] values) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(values.Select(v => new KeyValuePair<string, string?>(v.Key, v.Value)))
            .Build();

    private static string NewDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), "keyward-r3-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    private sealed class FakeEnvironment(string name) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = name;
        public string ApplicationName { get; set; } = "test";
        public string ContentRootPath { get; set; } = Path.GetTempPath();
        public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider { get; set; } = null!;
    }
}

/// <summary>
/// Review 3, reference shell booted for real (Development and Production): security headers and CSP, agent-API
/// mapping, the account form limiter, registration modes and invitations, session revalidation and the
/// secret-expiry date in the alert mail. Serial: every boot migrates and seeds the shared test database.
/// </summary>
[TestClass]
[DoNotParallelize]
public class Review3ShellTests
{
    private static readonly ConcurrentQueue<(string To, string Subject, BrandedEmailContent Content)> SentMail = new();

    [TestMethod, TestCategory("Integration")]
    public async Task Production_serves_security_headers_and_a_nonce_only_csp()
    {
        if (!await CanConnectAsync())
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        var kekDirectory = NewDirectory();
        try
        {
            await using var factory = new ShellFactory("Production", new Dictionary<string, string?>
            {
                [ShellStartupValidation.PublicBaseUrlKey] = "https://keyward.example.test",
                [ShellKek.DirectoryKey] = kekDirectory,
            }, contentRoot: NewDirectory());
            using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
            client.DefaultRequestHeaders.AcceptLanguage.ParseAdd("de");

            var response = await client.GetAsync("/Account/Login");
            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);

            var csp = string.Join(";", response.Headers.GetValues("Content-Security-Policy"));
            StringAssert.Contains(csp, "frame-ancestors 'none'");
            StringAssert.Contains(csp, "object-src 'none'");
            Assert.DoesNotContain("'unsafe-inline'", csp.Split(';').Single(d => d.Trim().StartsWith("script-src", StringComparison.Ordinal)));
            Assert.AreEqual("DENY", response.Headers.GetValues("X-Frame-Options").Single());
            Assert.AreEqual("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
            Assert.AreEqual("no-referrer", response.Headers.GetValues("Referrer-Policy").Single());
            Assert.IsTrue(response.Headers.Contains("Permissions-Policy"));

            var nonce = Regex.Match(csp, "'nonce-([^']+)'").Groups[1].Value;
            Assert.IsFalse(string.IsNullOrEmpty(nonce));

            var html = await response.Content.ReadAsStringAsync();
            StringAssert.Contains(html, "<html lang=\"de\"");
            Assert.DoesNotContain("onclick=\"", html, "Inline event handlers are blocked by the CSP.");
            // Every inline script (no src) carries this response's nonce.
            foreach (Match script in Regex.Matches(html, "<script(?![^>]*\\ssrc=)([^>]*)>"))
            {
                StringAssert.Contains(script.Groups[1].Value, $"nonce=\"{nonce}\"", script.Value);
            }

            // The agent API is not mapped unless enabled; the client API is.
            Assert.AreEqual(HttpStatusCode.NotFound, (await client.GetAsync("/keyward/api/v1/agent/ping")).StatusCode);
            Assert.AreEqual(HttpStatusCode.Unauthorized, (await client.GetAsync("/keyward/api/v1/ping")).StatusCode);

            // Logout without an antiforgery token is refused.
            Assert.AreEqual(HttpStatusCode.BadRequest, (await client.PostAsync("/account/logout", new FormUrlEncodedContent([]))).StatusCode);

            // InviteOnly (default) on an installation that has accounts: the register page offers no form.
            await EnsureAnyIdentityUserAsync(factory);
            var register = await (await client.GetAsync("/account/register")).Content.ReadAsStringAsync();
            Assert.DoesNotContain("name=\"Input.Password\"", register);
        }
        finally
        {
            Directory.Delete(kekDirectory, recursive: true);
        }
    }

    [TestMethod, TestCategory("Integration")]
    public async Task Account_form_posts_are_throttled_per_client_and_the_proxy_list_is_applied()
    {
        if (!await CanConnectAsync())
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        await using var factory = new ShellFactory("Development", new Dictionary<string, string?>
        {
            ["Keyward:AccountRateLimit:PermitLimit"] = "2",
            [ShellForwardedHeaders.KnownProxiesKey] = "10.1.2.3",
        });
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        HttpResponseMessage Post() => client.PostAsync("/account/forgot-password",
            new FormUrlEncodedContent([new("Input.Email", "nobody@example.test")])).GetAwaiter().GetResult();

        Assert.AreNotEqual(HttpStatusCode.TooManyRequests, Post().StatusCode);
        Assert.AreNotEqual(HttpStatusCode.TooManyRequests, Post().StatusCode);
        var limited = Post();
        Assert.AreEqual(HttpStatusCode.TooManyRequests, limited.StatusCode);
        StringAssert.Contains(await limited.Content.ReadAsStringAsync(), "Too many attempts");

        // GET is never throttled.
        Assert.AreEqual(HttpStatusCode.OK, (await client.GetAsync("/account/forgot-password")).StatusCode);

        var forwarded = factory.Services.GetRequiredService<IOptions<ForwardedHeadersOptions>>().Value;
        Assert.HasCount(1, forwarded.KnownProxies);
        Assert.AreEqual(IPAddress.Parse("10.1.2.3"), forwarded.KnownProxies[0]);
        Assert.IsEmpty(forwarded.KnownIPNetworks);
    }

    [TestMethod, TestCategory("Integration")]
    public async Task An_invitation_is_single_use_and_activates_the_account()
    {
        if (!await CanConnectAsync())
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        await using var factory = new ShellFactory("Development");
        _ = factory.Server;   // boot (migrations, seed)

        await using var scope = factory.Services.CreateAsyncScope();
        var invitations = scope.ServiceProvider.GetRequiredService<InvitationService>();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
        var email = $"invite-{Guid.NewGuid():N}@example.test";

        Assert.AreEqual(InvitationOutcome.InvalidEmail, await invitations.InviteAsync("not-an-address"));
        Assert.AreEqual(InvitationOutcome.Sent, await invitations.InviteAsync(email));

        var mail = SentMail.Last(m => m.To == email);
        StringAssert.StartsWith(mail.Content.ActionUrl, "https://localhost:7212/account/accept-invitation?userId=");

        var pending = (await users.FindByEmailAsync(email))!;
        Assert.IsTrue(InvitationService.IsPending(pending));
        Assert.IsFalse(await users.HasPasswordAsync(pending));

        // An invited account cannot be reached through sign-in or password reset, and is re-invitable.
        Assert.AreEqual(InvitationOutcome.Sent, await invitations.InviteAsync(email));
        var link = new Uri(SentMail.Last(m => m.To == email).Content.ActionUrl!);
        var query = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(link.Query);
        string userId = query["userId"]!, token = query["token"]!;

        var weak = await invitations.AcceptAsync(userId, token, "short");
        Assert.IsTrue(weak.LinkValid);
        Assert.IsFalse(weak.Result!.Succeeded);

        var accepted = await invitations.AcceptAsync(userId, token, "Correct-Horse-Battery-9");
        Assert.IsTrue(accepted.LinkValid);
        Assert.IsTrue(accepted.Result!.Succeeded);

        var active = (await users.FindByIdAsync(userId))!;
        Assert.IsTrue(active.EmailConfirmed);
        Assert.IsNull(active.LockoutEnd);
        Assert.IsTrue(await users.CheckPasswordAsync(active, "Correct-Horse-Battery-9"));

        // Spent: the same link no longer works, and the address is now an active account.
        Assert.IsFalse((await invitations.AcceptAsync(userId, token, "Another-Password-99")).LinkValid);
        Assert.AreEqual(InvitationOutcome.AlreadyActive, await invitations.InviteAsync(email));
    }

    [TestMethod, TestCategory("Integration")]
    public async Task A_circuit_session_ends_when_the_security_stamp_changes_or_the_account_is_disabled()
    {
        if (!await CanConnectAsync())
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        await using var factory = new ShellFactory("Development");
        _ = factory.Server;

        await using var scope = factory.Services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
        var identityOptions = scope.ServiceProvider.GetRequiredService<IOptions<IdentityOptions>>();
        var principals = new UserClaimsPrincipalFactory<IdentityUser>(users, identityOptions);

        var user = new IdentityUser { UserName = $"reval-{Guid.NewGuid():N}@example.test" };
        user.Email = user.UserName;
        Assert.IsTrue((await users.CreateAsync(user, "Correct-Horse-Battery-9")).Succeeded);

        var principal = await principals.CreateAsync(user);
        Assert.IsTrue(await IdentityRevalidatingAuthenticationStateProvider.IsStillValidAsync(users, identityOptions.Value, principal));

        await users.UpdateSecurityStampAsync(user);
        Assert.IsFalse(await IdentityRevalidatingAuthenticationStateProvider.IsStillValidAsync(users, identityOptions.Value, principal));

        var fresh = await principals.CreateAsync(user);
        await users.SetLockoutEndDateAsync(user, DateTimeOffset.MaxValue);
        Assert.IsFalse(await IdentityRevalidatingAuthenticationStateProvider.IsStillValidAsync(users, identityOptions.Value, fresh));

        await users.DeleteAsync(user);
    }

    [TestMethod, TestCategory("Integration")]
    public async Task The_secret_expiry_mail_shows_the_stored_date_east_of_utc()
    {
        if (!await CanConnectAsync())
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        await using var factory = new ShellFactory("Development", new Dictionary<string, string?>
        {
            ["Keyward:Monitoring:TimeZone"] = "Tokyo Standard Time",
        });
        _ = factory.Server;

        await using var scope = factory.Services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
        var email = $"expiry-{Guid.NewGuid():N}@example.test";
        var user = new IdentityUser { UserName = email, Email = email };
        Assert.IsTrue((await users.CreateAsync(user)).Succeeded);

        try
        {
            var presenter = scope.ServiceProvider.GetRequiredService<IKeywardAlertPresenter>();
            var sent = await presenter.NotifySecretExpiryAsync(
                Demo.TenantId,
                [new KeywardAlertRecipient(Guid.NewGuid(), user.Id)],
                [new KeywardSecretExpiryLine("API_KEY", "demo", "Production", 5, new DateTimeOffset(2026, 12, 31, 23, 59, 59, TimeSpan.Zero), "")]);

            Assert.AreEqual(1, sent);
            var text = string.Join("\n", SentMail.Last(m => m.To == email).Content.Paragraphs);
            StringAssert.Contains(text, "2026-12-31");
            Assert.DoesNotContain("2027-01-01", text);
        }
        finally
        {
            await users.DeleteAsync(user);
        }
    }

    private static async Task EnsureAnyIdentityUserAsync(WebApplicationFactory<Program> factory)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
        if (!users.Users.Any())
        {
            var email = $"seed-{Guid.NewGuid():N}@example.test";
            await users.CreateAsync(new IdentityUser { UserName = email, Email = email });
        }
    }

    private sealed class ShellFactory(string environment, Dictionary<string, string?>? settings = null, string? contentRoot = null)
        : WebApplicationFactory<Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment(environment);
            if (contentRoot is not null)
            {
                builder.UseContentRoot(contentRoot);
            }

            builder.UseSetting("ConnectionStrings:Keyward", TestConfig.ConnectionString);
            foreach (var (key, value) in settings ?? [])
            {
                builder.UseSetting(key, value);
            }

            builder.ConfigureTestServices(services =>
            {
                // Background services stay off (see ReferenceShellStartupTests); mails are captured, not sent.
                services.RemoveAll<IHostedService>();
                services.RemoveAll<IAccountEmailSender>();
                services.AddSingleton<IAccountEmailSender, CapturingSender>();
            });
        }
    }

    private sealed class CapturingSender : IAccountEmailSender
    {
        public Task SendPasswordResetLinkAsync(string email, string resetLink, CancellationToken ct = default) =>
            SendAsync(email, "reset", new BrandedEmailContent { Brand = "", Title = "", Paragraphs = [], ActionUrl = resetLink }, ct);

        public Task SendEmailConfirmationLinkAsync(string email, string confirmLink, CancellationToken ct = default) =>
            SendAsync(email, "confirm", new BrandedEmailContent { Brand = "", Title = "", Paragraphs = [], ActionUrl = confirmLink }, ct);

        public Task SendAsync(string email, string subject, BrandedEmailContent content, CancellationToken ct = default)
        {
            SentMail.Enqueue((email, subject, content));
            return Task.CompletedTask;
        }
    }

    private static string NewDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), "keyward-r3-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    private static async Task<bool> CanConnectAsync()
    {
        try
        {
            await using var connection = new SqlConnection(TestConfig.ConnectionString);
            await connection.OpenAsync();
            return true;
        }
        catch (SqlException)
        {
            return false;
        }
    }
}
