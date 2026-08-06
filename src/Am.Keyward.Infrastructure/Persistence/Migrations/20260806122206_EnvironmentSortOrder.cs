using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Am.Keyward.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class EnvironmentSortOrder : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "SortOrder",
                schema: "amkeyward",
                table: "TenantDefaultEnvironments",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<int>(
                name: "SortOrder",
                schema: "amkeyward",
                table: "RuntimeEnvironments",
                type: "int",
                nullable: false,
                defaultValue: 0);

            // Backfill existing rows: the built-in set keeps its canonical order (Development, Test,
            // Production), any other names follow alphabetically. New rows get their SortOrder assigned
            // by the application (creation order), so this ranking runs exactly once.
            //
            // Both tables sit in the row-level-security policy (FILTER + BLOCK AFTER UPDATE), and the
            // migration connection has no SESSION_CONTEXT('TenantId') — without the SystemBypass escape
            // (see fn_TenantAccessPredicate since AuditSystemReadBypass) the UPDATE would silently see
            // zero rows. The bypass is scoped to this batch and reset immediately after.
            migrationBuilder.Sql("""
                EXEC sp_set_session_context @key = N'SystemBypass', @value = 1;

                WITH RankedEnvironments AS (
                    SELECT SortOrder,
                           ROW_NUMBER() OVER (
                               PARTITION BY ProjectId
                               ORDER BY CASE Name
                                            WHEN 'Development' THEN 0
                                            WHEN 'Test' THEN 1
                                            WHEN 'Production' THEN 2
                                            ELSE 3
                                        END, Name) - 1 AS NewOrder
                    FROM [amkeyward].[RuntimeEnvironments]
                )
                UPDATE RankedEnvironments SET SortOrder = NewOrder;

                WITH RankedDefaults AS (
                    SELECT SortOrder,
                           ROW_NUMBER() OVER (
                               PARTITION BY TenantId
                               ORDER BY CASE Name
                                            WHEN 'Development' THEN 0
                                            WHEN 'Test' THEN 1
                                            WHEN 'Production' THEN 2
                                            ELSE 3
                                        END, Name) - 1 AS NewOrder
                    FROM [amkeyward].[TenantDefaultEnvironments]
                )
                UPDATE RankedDefaults SET SortOrder = NewOrder;

                EXEC sp_set_session_context @key = N'SystemBypass', @value = 0;
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "SortOrder",
                schema: "amkeyward",
                table: "TenantDefaultEnvironments");

            migrationBuilder.DropColumn(
                name: "SortOrder",
                schema: "amkeyward",
                table: "RuntimeEnvironments");
        }
    }
}
