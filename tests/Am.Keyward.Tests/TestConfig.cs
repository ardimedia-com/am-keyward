using Microsoft.Extensions.Configuration;

namespace Am.Keyward.Tests;

/// <summary>
/// Central test configuration. The database connection string comes from <c>appsettings.json</c> (a localhost
/// default committed in the repo, no secret), overridable by the standard <c>ConnectionStrings__Keyward</c>
/// environment variable so CI can point the integration tests at a SQL-auth server (its password stays in a
/// CI secret, never in the repo). The tests use their OWN database (<c>amkeywardtest</c>) — never the app's
/// dev database <c>amkeyward</c>, whose data would otherwise be polluted with seeded test users/tenants.
/// </summary>
internal static class TestConfig
{
    public static string ConnectionString { get; } = Build();

    private static string Build()
    {
        var config = new ConfigurationBuilder()
            .SetBasePath(AppContext.BaseDirectory)
            .AddJsonFile("appsettings.json", optional: true)
            .AddEnvironmentVariables()
            .Build();

        return config.GetConnectionString("Keyward")
            ?? "Server=localhost;Database=amkeywardtest;Integrated Security=True;Encrypt=False";
    }
}
