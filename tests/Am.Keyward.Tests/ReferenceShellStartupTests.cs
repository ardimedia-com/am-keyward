using System.Net;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

namespace Am.Keyward.Tests;

/// <summary>
/// Boots the reference shell (<c>Am.Keyward.Ui.Blazor.App</c>) for real and sends requests through its full
/// pipeline. 0.17.0-preview shipped a shell that refused to start (a minimal-API parameter binding error) and no
/// test noticed, because none ever started it. This one does, against the test database.
/// </summary>
[TestClass]
public class ReferenceShellStartupTests
{
    [TestMethod, TestCategory("Integration")]
    public async Task The_reference_shell_starts_and_serves_its_endpoints()
    {
        if (!await CanConnectAsync())
        {
            Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
            return;
        }

        await using var factory = new ShellFactory();
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        // Guard: the shell must run against the TEST database, never the developer's.
        using (var scope = factory.Services.CreateScope())
        {
            var database = new SqlConnectionStringBuilder(
                scope.ServiceProvider.GetRequiredService<KeywardDbContext>().Database.GetConnectionString()).InitialCatalog;
            Assert.AreEqual(new SqlConnectionStringBuilder(TestConfig.ConnectionString).InitialCatalog, database);
        }

        // Every request builds the full endpoint set — where a binding error surfaces.
        Assert.AreEqual(HttpStatusCode.OK, (await client.GetAsync("/Account/Login")).StatusCode);
        Assert.AreEqual(HttpStatusCode.Unauthorized, (await client.GetAsync("/keyward/api/v1/agent/ping")).StatusCode);
        Assert.AreEqual(HttpStatusCode.Unauthorized, (await client.GetAsync("/keyward/api/v1/ping")).StatusCode);

        // A protected Keyward page sends an anonymous visitor to the login.
        var page = await client.GetAsync("/amkeyward/agent-tokens");
        Assert.AreEqual(HttpStatusCode.Redirect, page.StatusCode);
        StringAssert.Contains(page.Headers.Location!.ToString(), "/Account/Login");
    }

    private sealed class ShellFactory : WebApplicationFactory<Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Development");
            builder.UseSetting("ConnectionStrings:Keyward", TestConfig.ConnectionString);

            // Background services stay off: the KEK integrity check would seal the shared test database with the
            // shell's key, and the others poll on timers no test waits for.
            builder.ConfigureTestServices(services => services.RemoveAll<IHostedService>());
        }
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
