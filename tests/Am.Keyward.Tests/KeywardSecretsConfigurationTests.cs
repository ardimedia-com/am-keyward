using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Am.Keyward.Client;
using Microsoft.Extensions.Configuration;

namespace Am.Keyward.Tests;

/// <summary>
/// The Am.Keyward.Client configuration source: AddKeywardSecrets loads the bulk read into IConfiguration,
/// resolves the token by the shared env-var convention, fails loudly (or stays empty when Optional), and
/// picks up changes on the reload interval. HTTP is stubbed at the handler, so these are pure unit tests.
/// </summary>
[TestClass]
public class KeywardSecretsConfigurationTests
{
    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        private readonly List<HttpRequestMessage> requests = [];

        public Func<HttpRequestMessage, HttpResponseMessage> Respond { get; set; } = respond;

        public int RequestCount { get { lock (requests) { return requests.Count; } } }

        public HttpRequestMessage LastRequest { get { lock (requests) { return requests[^1]; } } }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            lock (requests)
            {
                requests.Add(request);
            }

            return Task.FromResult(Respond(request));
        }
    }

    private static HttpResponseMessage Json(object payload) =>
        new(HttpStatusCode.OK) { Content = JsonContent.Create(payload) };

    [TestMethod, TestCategory("Unit")]
    public void Bulk_load_feeds_IConfiguration()
    {
        var handler = new StubHandler(_ => Json(new Dictionary<string, string>
        {
            ["ConnectionStrings:Main"] = "Server=.;Database=app",
            ["Smtp:Host"] = "smtp.bvd.li",
        }));

        var config = new ConfigurationBuilder()
            .AddKeywardSecrets(o =>
            {
                o.ServiceUri = new Uri("https://keyward.example.com");
                o.Token = "test-token";
                o.HttpMessageHandler = handler;
            })
            .Build();

        using var _ = (IDisposable)config;
        Assert.AreEqual("Server=.;Database=app", config.GetConnectionString("Main"));
        Assert.AreEqual("smtp.bvd.li", config["smtp:host"]); // configuration keys are case-insensitive
        Assert.AreEqual("/keyward/api/v1/secrets", handler.LastRequest.RequestUri!.AbsolutePath);
        Assert.AreEqual(new AuthenticationHeaderValue("Bearer", "test-token"), handler.LastRequest.Headers.Authorization);
    }

    [TestMethod, TestCategory("Unit")]
    public async Task Create_builds_a_standalone_client_whose_ping_hits_the_ping_endpoint()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.NoContent));

        using var client = KeywardSecretsClient.Create(o =>
        {
            o.ServiceUri = new Uri("https://keyward.example.com");
            o.Token = "test-token";
            o.HttpMessageHandler = handler;
        });
        await client.PingAsync();

        Assert.AreEqual("/keyward/api/v1/ping", handler.LastRequest.RequestUri!.AbsolutePath);
        Assert.AreEqual(new AuthenticationHeaderValue("Bearer", "test-token"), handler.LastRequest.Headers.Authorization);
    }

    [TestMethod, TestCategory("Unit")]
    public void Create_without_a_token_names_the_environment_variable_it_looked_for()
    {
        var ex = Assert.ThrowsExactly<InvalidOperationException>(() => KeywardSecretsClient.Create(o =>
        {
            o.ServiceUri = new Uri("https://keyward.example.com");
            o.ApplicationName = "Keyward.Client.Test.Missing";
        }));

        StringAssert.Contains(ex.Message, "KEYWARD_KEYWARD_CLIENT_TEST_MISSING_TOKEN");
    }

    [TestMethod, TestCategory("Unit")]
    public async Task Ping_surfaces_a_rejected_token_as_an_exception()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.Unauthorized));

        using var client = KeywardSecretsClient.Create(o =>
        {
            o.ServiceUri = new Uri("https://keyward.example.com");
            o.Token = "revoked";
            o.HttpMessageHandler = handler;
        });

        await Assert.ThrowsExactlyAsync<HttpRequestException>(() => client.PingAsync());
    }

    [TestMethod, TestCategory("Unit")]
    public void A_ServiceUri_with_a_sub_path_keeps_it()
    {
        var handler = new StubHandler(_ => Json(new Dictionary<string, string>()));

        using var config = (IDisposable)new ConfigurationBuilder()
            .AddKeywardSecrets(o =>
            {
                o.ServiceUri = new Uri("https://host.example.com/vault"); // installation hosted under a sub-path
                o.Token = "t";
                o.HttpMessageHandler = handler;
            })
            .Build();

        Assert.AreEqual("/vault/keyward/api/v1/secrets", handler.LastRequest.RequestUri!.AbsolutePath);
    }

    [TestMethod, TestCategory("Unit")]
    public void Token_is_read_from_the_derived_environment_variable()
    {
        const string variable = "KEYWARD_KEYWARD_CLIENT_TEST_DERIVED_TOKEN";
        Environment.SetEnvironmentVariable(variable, "from-env");
        try
        {
            var handler = new StubHandler(_ => Json(new Dictionary<string, string>()));

            using var config = (IDisposable)new ConfigurationBuilder()
                .AddKeywardSecrets(o =>
                {
                    o.ServiceUri = new Uri("https://keyward.example.com");
                    o.ApplicationName = "Keyward.Client.Test.Derived";
                    o.HttpMessageHandler = handler;
                })
                .Build();

            Assert.AreEqual("from-env", handler.LastRequest.Headers.Authorization!.Parameter);
        }
        finally
        {
            Environment.SetEnvironmentVariable(variable, null);
        }
    }

    [TestMethod, TestCategory("Unit")]
    public void An_explicit_token_wins_over_the_environment_variable()
    {
        const string variable = "KEYWARD_KEYWARD_CLIENT_TEST_EXPLICIT_TOKEN";
        Environment.SetEnvironmentVariable(variable, "from-env");
        try
        {
            var handler = new StubHandler(_ => Json(new Dictionary<string, string>()));

            using var config = (IDisposable)new ConfigurationBuilder()
                .AddKeywardSecrets(o =>
                {
                    o.ServiceUri = new Uri("https://keyward.example.com");
                    o.ApplicationName = "Keyward.Client.Test.Explicit";
                    o.Token = "explicit";
                    o.HttpMessageHandler = handler;
                })
                .Build();

            Assert.AreEqual("explicit", handler.LastRequest.Headers.Authorization!.Parameter);
        }
        finally
        {
            Environment.SetEnvironmentVariable(variable, null);
        }
    }

    [TestMethod, TestCategory("Unit")]
    public void Missing_token_and_Optional_yields_an_empty_source_without_a_request()
    {
        var handler = new StubHandler(_ => Json(new Dictionary<string, string>()));

        var config = new ConfigurationBuilder()
            .AddKeywardSecrets(o =>
            {
                o.ServiceUri = new Uri("https://keyward.example.com");
                o.ApplicationName = "Keyward.Client.Test.Unset.Optional"; // its env variable is not set
                o.Optional = true;
                o.HttpMessageHandler = handler;
            })
            .Build();

        using var _ = (IDisposable)config;
        Assert.IsNull(config["anything"]);
        Assert.AreEqual(0, handler.RequestCount);
    }

    [TestMethod, TestCategory("Unit")]
    public void Missing_token_fails_the_build_naming_the_variable()
    {
        var builder = new ConfigurationBuilder()
            .AddKeywardSecrets(o =>
            {
                o.ServiceUri = new Uri("https://keyward.example.com");
                o.ApplicationName = "Keyward.Client.Test.Unset.Required";
            });

        var ex = Assert.ThrowsExactly<InvalidOperationException>(() => builder.Build());
        StringAssert.Contains(ex.Message, "KEYWARD_KEYWARD_CLIENT_TEST_UNSET_REQUIRED_TOKEN");
    }

    [TestMethod, TestCategory("Unit")]
    public void Missing_ServiceUri_fails_at_Add_time()
    {
        var builder = new ConfigurationBuilder();
        Assert.ThrowsExactly<InvalidOperationException>(() => builder.AddKeywardSecrets(o => o.Token = "t"));
    }

    [TestMethod, TestCategory("Unit")]
    public void Unreachable_server_and_Optional_stays_empty()
    {
        var handler = new StubHandler(_ => throw new HttpRequestException("connection refused"));

        var config = new ConfigurationBuilder()
            .AddKeywardSecrets(o =>
            {
                o.ServiceUri = new Uri("https://keyward.example.com");
                o.Token = "t";
                o.Optional = true;
                o.LoadRetryCount = 0;
                o.HttpMessageHandler = handler;
            })
            .Build();

        using var _ = (IDisposable)config;
        Assert.IsNull(config["anything"]);
    }

    [TestMethod, TestCategory("Unit")]
    public void Unreachable_server_fails_after_the_startup_retries()
    {
        var handler = new StubHandler(_ => throw new HttpRequestException("connection refused"));

        var builder = new ConfigurationBuilder()
            .AddKeywardSecrets(o =>
            {
                o.ServiceUri = new Uri("https://keyward.example.com");
                o.Token = "t";
                o.LoadRetryCount = 1;
                o.LoadRetryDelay = TimeSpan.FromMilliseconds(10);
                o.HttpMessageHandler = handler;
            });

        var ex = Assert.ThrowsExactly<InvalidOperationException>(() => builder.Build());
        Assert.IsInstanceOfType<HttpRequestException>(ex.InnerException);
        Assert.AreEqual(2, handler.RequestCount); // the initial attempt + one retry
    }

    [TestMethod, TestCategory("Unit")]
    public void Reload_picks_up_changed_secrets()
    {
        var handler = new StubHandler(_ => Json(new Dictionary<string, string> { ["Feature:Level"] = "v1" }));

        var config = new ConfigurationBuilder()
            .AddKeywardSecrets(o =>
            {
                o.ServiceUri = new Uri("https://keyward.example.com");
                o.Token = "t";
                o.ReloadInterval = TimeSpan.FromMilliseconds(50);
                o.HttpMessageHandler = handler;
            })
            .Build();

        using var _ = (IDisposable)config;
        Assert.AreEqual("v1", config["Feature:Level"]);

        var reloaded = false;
        config.GetReloadToken().RegisterChangeCallback(_ => reloaded = true, null);
        handler.Respond = _ => Json(new Dictionary<string, string> { ["Feature:Level"] = "v2" });

        var stopwatch = Stopwatch.StartNew();
        while (config["Feature:Level"] != "v2" && stopwatch.Elapsed < TimeSpan.FromSeconds(10))
        {
            Thread.Sleep(20);
        }

        Assert.AreEqual("v2", config["Feature:Level"]);
        Assert.IsTrue(reloaded, "the configuration reload token should have fired");
    }

    [TestMethod, TestCategory("Unit")]
    public async Task Typed_client_reads_one_secret_and_maps_404_to_null()
    {
        var handler = new StubHandler(request =>
            request.RequestUri!.AbsolutePath == "/keyward/api/v1/secrets/ConnectionStrings%3AMain"
                ? Json(new { key = "ConnectionStrings:Main", value = "Server=.;Database=app" })
                : new HttpResponseMessage(HttpStatusCode.NotFound));

        using var http = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://keyward.example.com/keyward/api/v1/"),
        };
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "t");
        var client = new KeywardSecretsClient(http);

        Assert.AreEqual("Server=.;Database=app", await client.GetAsync("ConnectionStrings:Main"));
        Assert.IsNull(await client.GetAsync("does-not-exist"));
    }

    [TestMethod, TestCategory("Unit")]
    public async Task Typed_client_bulk_read_returns_all_pairs()
    {
        var handler = new StubHandler(_ => Json(new Dictionary<string, string> { ["A"] = "1", ["B"] = "2" }));
        using var http = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://keyward.example.com/keyward/api/v1/"),
        };

        var all = await new KeywardSecretsClient(http).GetAllAsync();
        Assert.AreEqual(2, all.Count);
        Assert.AreEqual("1", all["A"]);
    }
}
