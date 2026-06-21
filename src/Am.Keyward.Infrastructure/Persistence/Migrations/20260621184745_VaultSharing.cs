using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Am.Keyward.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class VaultSharing : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "AccessGrants",
                schema: "amkeyward",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    PrincipalType = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false),
                    PrincipalId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ScopeKind = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false),
                    ScopeTargetId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Permission = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false),
                    CreatedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AccessGrants", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AccessGrants_PrincipalType_PrincipalId",
                schema: "amkeyward",
                table: "AccessGrants",
                columns: new[] { "PrincipalType", "PrincipalId" });

            migrationBuilder.CreateIndex(
                name: "IX_AccessGrants_TenantId",
                schema: "amkeyward",
                table: "AccessGrants",
                column: "TenantId");

            // Access grants are tenant-scoped; reuse the tenant predicate (cross-tenant grants are forbidden).
            migrationBuilder.Sql(@"
                ALTER SECURITY POLICY amkeyward.TenantIsolationPolicy
                    ADD FILTER PREDICATE amkeyward.fn_TenantAccessPredicate(TenantId) ON amkeyward.AccessGrants,
                    ADD BLOCK PREDICATE amkeyward.fn_TenantAccessPredicate(TenantId) ON amkeyward.AccessGrants AFTER INSERT,
                    ADD BLOCK PREDICATE amkeyward.fn_TenantAccessPredicate(TenantId) ON amkeyward.AccessGrants AFTER UPDATE;");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(@"
                ALTER SECURITY POLICY amkeyward.TenantIsolationPolicy
                    DROP FILTER PREDICATE ON amkeyward.AccessGrants,
                    DROP BLOCK PREDICATE ON amkeyward.AccessGrants AFTER INSERT,
                    DROP BLOCK PREDICATE ON amkeyward.AccessGrants AFTER UPDATE;");

            migrationBuilder.DropTable(
                name: "AccessGrants",
                schema: "amkeyward");
        }
    }
}
