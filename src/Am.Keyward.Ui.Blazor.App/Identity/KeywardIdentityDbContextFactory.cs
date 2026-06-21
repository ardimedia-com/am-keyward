using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Am.Keyward.Ui.Blazor.App.Identity;

/// <summary>Design-time factory so <c>dotnet ef</c> can build the Identity context's migrations.</summary>
public sealed class KeywardIdentityDbContextFactory : IDesignTimeDbContextFactory<KeywardIdentityDbContext>
{
    public KeywardIdentityDbContext CreateDbContext(string[] args)
    {
        var connectionString = Environment.GetEnvironmentVariable("AMKEYWARD_DB")
            ?? "Server=localhost;Database=amkeyward;Integrated Security=True;Encrypt=False";

        var options = new DbContextOptionsBuilder<KeywardIdentityDbContext>()
            .UseSqlServer(connectionString, sql =>
                sql.MigrationsHistoryTable("__EFMigrationsHistory", KeywardIdentityDbContext.Schema))
            .Options;

        return new KeywardIdentityDbContext(options);
    }
}
