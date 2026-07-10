using Microsoft.EntityFrameworkCore;

namespace Am.Keyward.Infrastructure.Persistence;

/// <summary>
/// Applies AM KEYWARD's EF Core migrations (schema <c>amkeyward</c>) through a caller-supplied connection, so
/// a host can migrate the schema WITHOUT its least-privilege runtime login needing DDL rights. Pass a
/// PRIVILEGED (DDL-capable) connection — a dedicated migrator login, or, when the <c>amkeyward</c> schema is
/// embedded in the host's own database, the host's existing privileged connection to that database. Runtime
/// queries keep using the least-privilege login, so SQL Server row-level security stays enforced (the
/// two-login model, see docs/database-logins.md).
///
/// These are the same migrations as <c>KeywardDbContext.Database.Migrate()</c> and as a generated idempotent
/// SQL script (<c>dotnet ef migrations script --idempotent --context KeywardDbContext</c>), so calling this is
/// interchangeable with either; it is idempotent (pending migrations are applied, an up-to-date schema is a
/// no-op). Best-effort error handling is the host's responsibility — wrap the call so a migration failure
/// degrades AM KEYWARD to "unavailable" rather than crashing the host, if that is the desired posture.
/// </summary>
public static class KeywardSchemaMigrator
{
    /// <summary>
    /// Migrates the <c>amkeyward</c> schema using <paramref name="connectionString"/> (a DDL-capable
    /// connection to the database that hosts the schema).
    /// </summary>
    public static async Task MigrateAsync(string connectionString, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);

        DbContextOptions<KeywardDbContext> options = new DbContextOptionsBuilder<KeywardDbContext>()
            .UseSqlServer(connectionString, sql =>
                sql.MigrationsHistoryTable("__EFMigrationsHistory", KeywardDbContext.Schema))
            .Options;

        // Migrations only build/apply the model — no tenant/user scope is used (the same NoScope the
        // design-time factory uses).
        await using KeywardDbContext context = new(options, NoScope.Instance, NoScope.Instance);
        await context.Database.MigrateAsync(cancellationToken);
    }
}
