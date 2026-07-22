using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Am.Keyward.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class VaultItemPublicId : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "PublicId",
                schema: "amkeyward",
                table: "VaultItems",
                type: "uniqueidentifier",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            // Existing rows all landed on the empty-GUID default; give each a distinct value BEFORE the unique
            // index is created, otherwise it collides. The catch: VaultItems carries the tenant-isolation RLS
            // policy, and this migration runs WITHOUT a tenant SESSION_CONTEXT, so the FILTER predicate hides
            // every existing row from the UPDATE — it would touch 0 rows and leave them all on the empty GUID,
            // while CREATE UNIQUE INDEX (which is not RLS-filtered) then sees the duplicates and fails, rolling
            // the whole migration back. So disable the policy for the backfill + index, then restore it.
            // Guarded, so it is a harmless no-op if the policy isn't present yet (fresh DB / different order).
            migrationBuilder.Sql(@"
IF EXISTS (SELECT 1 FROM sys.security_policies sp JOIN sys.schemas s ON s.schema_id = sp.schema_id
           WHERE sp.name = 'TenantIsolationPolicy' AND s.name = 'amkeyward')
    ALTER SECURITY POLICY amkeyward.TenantIsolationPolicy WITH (STATE = OFF);");

            migrationBuilder.Sql("UPDATE amkeyward.VaultItems SET PublicId = NEWID();");

            migrationBuilder.CreateIndex(
                name: "IX_VaultItems_PublicId",
                schema: "amkeyward",
                table: "VaultItems",
                column: "PublicId",
                unique: true);

            migrationBuilder.Sql(@"
IF EXISTS (SELECT 1 FROM sys.security_policies sp JOIN sys.schemas s ON s.schema_id = sp.schema_id
           WHERE sp.name = 'TenantIsolationPolicy' AND s.name = 'amkeyward')
    ALTER SECURITY POLICY amkeyward.TenantIsolationPolicy WITH (STATE = ON);");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_VaultItems_PublicId",
                schema: "amkeyward",
                table: "VaultItems");

            migrationBuilder.DropColumn(
                name: "PublicId",
                schema: "amkeyward",
                table: "VaultItems");
        }
    }
}
