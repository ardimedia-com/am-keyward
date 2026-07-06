using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Am.Keyward.Infrastructure;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Am.Keyward.Tests;

/// <summary>
/// Assembly-wide test bootstrap. It applies the <see cref="KeywardDbContext"/> migrations (creating the
/// <c>amkeyward</c> database and its schema, including the row-level-security policy) so the integration tests
/// have a schema without a separate <c>dotnet ef</c> step, and provisions the least-privilege
/// <c>amkeyward_app</c> login from <c>db/setup-logins.sql</c> with generated passwords — publishing its
/// connection string as <c>KEYWARD_APP_TEST_CONNECTION</c> so the row-level-security test runs everywhere,
/// not only where an operator set it by hand. Everything is best-effort: if SQL is unreachable or the current
/// login cannot create server logins, the affected tests fall back to their own <c>Assert.Inconclusive</c>.
/// </summary>
[TestClass]
public static class TestDatabaseSetup
{
    [AssemblyInitialize]
    public static async Task InitializeAsync(TestContext _)
    {
        var connectionString = TestConfig.ConnectionString;

        await using var provider = new ServiceCollection()
            .AddKeyward(connectionString, RandomNumberGenerator.GetBytes(32), "test-kek:v1")
            .BuildServiceProvider();
        using var scope = provider.CreateScope();

        try
        {
            // Creates the database if absent and applies every migration (schema + RLS policy). No-op when the
            // local database is already up to date.
            await scope.ServiceProvider.GetRequiredService<KeywardDbContext>().Database.MigrateAsync();
        }
        catch when (!IsCi)
        {
            return; // Local: SQL unreachable or no DDL rights — the integration tests skip themselves.
        }
        // In CI (CI=true) a migration failure is NOT swallowed: the integration/isolation tests must actually
        // run, so an unreachable database fails the build instead of silently skipping.

        try
        {
            var appPassword = GenerateStrongPassword();
            await ProvisionLoginsAsync(connectionString, GenerateStrongPassword(), appPassword);

            var appConnectionString = new SqlConnectionStringBuilder(connectionString)
            {
                IntegratedSecurity = false,
                UserID = "amkeyward_app",
                Password = appPassword,
            }.ConnectionString;
            Environment.SetEnvironmentVariable("KEYWARD_APP_TEST_CONNECTION", appConnectionString);
        }
        catch when (!IsCi)
        {
            // Local: provisioning server logins needs a sysadmin connection; where it is unavailable the
            // row-level-security test stays inconclusive (the app-layer isolation tests still run). In CI this
            // is not swallowed, so the RLS test is guaranteed to run.
        }
    }

    private static bool IsCi =>
        string.Equals(Environment.GetEnvironmentVariable("CI"), "true", StringComparison.OrdinalIgnoreCase);

    /// <summary>Runs the real <c>db/setup-logins.sql</c> (with generated passwords) batch-by-batch — EF/ADO
    /// cannot execute a multi-batch <c>GO</c> script in one call, so split on the <c>GO</c> separators.</summary>
    private static async Task ProvisionLoginsAsync(string sysadminConnectionString, string migratorPassword, string appPassword)
    {
        var scriptPath = Path.Combine(AppContext.BaseDirectory, "setup-logins.sql");
        if (!File.Exists(scriptPath))
        {
            return;
        }

        var script = (await File.ReadAllTextAsync(scriptPath))
            .Replace("<set-a-strong-migrator-password>", migratorPassword)
            .Replace("<set-a-strong-app-password>", appPassword);

        await using var connection = new SqlConnection(sysadminConnectionString);
        await connection.OpenAsync();
        foreach (var batch in Regex.Split(script, @"(?im)^[ \t]*GO[ \t]*$"))
        {
            if (string.IsNullOrWhiteSpace(batch))
            {
                continue;
            }

            await using var command = connection.CreateCommand();
            command.CommandText = batch;
            await command.ExecuteNonQueryAsync();
        }

        // The script's CREATE LOGIN is guarded (IF SUSER_ID IS NULL), so on a machine where the login already
        // exists it keeps its previous password — which would not match this run's generated one. Force the
        // app login's password to this run's value so the connection string below always works (the password
        // is self-generated, never user input; escape defensively). ALTER LOGIN takes no parameter binding.
        await using var alter = connection.CreateCommand();
        alter.CommandText = $"ALTER LOGIN [amkeyward_app] WITH PASSWORD = N'{appPassword.Replace("'", "''")}';";
        await alter.ExecuteNonQueryAsync();
    }

    // A random password that satisfies SQL Server's CHECK_POLICY = ON (length + all four character classes).
    private static string GenerateStrongPassword() =>
        "Aa1!" + Convert.ToBase64String(RandomNumberGenerator.GetBytes(24)).Replace('+', '-').Replace('/', '_').TrimEnd('=');
}
