using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Am.Keyward.Infrastructure.Persistence;

/// <summary>
/// Design-time factory so <c>dotnet ef</c> can create the context without booting the app. The runtime
/// uses the connection string the host supplies (see the DI registration); here we default to the local
/// SQL Server instance, overridable via the <c>AMKEYWARD_DB</c> environment variable.
/// </summary>
public sealed class KeywardDbContextFactory : IDesignTimeDbContextFactory<KeywardDbContext>
{
    public const string DefaultConnectionString =
        "Server=localhost;Database=amkeyward;Integrated Security=True;Encrypt=False";

    public KeywardDbContext CreateDbContext(string[] args)
    {
        var connectionString =
            Environment.GetEnvironmentVariable("AMKEYWARD_DB") ?? DefaultConnectionString;

        var options = new DbContextOptionsBuilder<KeywardDbContext>()
            .UseSqlServer(connectionString, sql =>
                sql.MigrationsHistoryTable("__EFMigrationsHistory", KeywardDbContext.Schema))
            .Options;

        // Design-time only builds/queries the model for migrations; no tenant/user scope is needed.
        return new KeywardDbContext(options, NoScope.Instance, NoScope.Instance);
    }
}
