using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;

namespace Am.Keyward.Infrastructure.Persistence;

/// <summary>Classifies database errors the services turn into domain outcomes (conflicts) instead of 500s.</summary>
internal static class DbUpdateExceptions
{
    /// <summary>SQL Server «Cannot insert duplicate key row» (unique index) and «Violation of UNIQUE KEY constraint».</summary>
    public static bool IsUniqueViolation(this DbUpdateException ex) =>
        ex.InnerException is SqlException { Number: 2601 or 2627 };

    /// <summary>True when the unique violation is on the named index or constraint.</summary>
    public static bool IsUniqueViolationOn(this DbUpdateException ex, string indexName) =>
        ex.IsUniqueViolation() && ex.InnerException!.Message.Contains(indexName, StringComparison.OrdinalIgnoreCase);
}
