using Am.Keyward.Core.Abstractions;
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
        return new KeywardDbContext(options, DesignTimeScope.Instance, DesignTimeScope.Instance);
    }

    /// <summary>A no-tenant/no-user context for design-time model building (migrations don't run scoped queries).</summary>
    private sealed class DesignTimeScope : ICurrentTenant, ICurrentUser
    {
        public static readonly DesignTimeScope Instance = new();

        public Guid? TenantId => null;

        public Guid? UserId => null;

        public bool IsAuthenticated => false;
    }
}
