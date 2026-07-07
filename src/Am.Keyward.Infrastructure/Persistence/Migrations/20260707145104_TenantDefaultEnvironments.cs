using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Am.Keyward.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class TenantDefaultEnvironments : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "TenantDefaultEnvironments",
                schema: "amkeyward",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TenantDefaultEnvironments", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_TenantDefaultEnvironments_TenantId_Name",
                schema: "amkeyward",
                table: "TenantDefaultEnvironments",
                columns: new[] { "TenantId", "Name" },
                unique: true);

            // Row-level security: tenant content — same coverage as the other tenant-scoped tables
            // (defense in depth behind the EF query filter).
            migrationBuilder.Sql(@"
                ALTER SECURITY POLICY amkeyward.TenantIsolationPolicy
                    ADD FILTER PREDICATE amkeyward.fn_TenantAccessPredicate(TenantId) ON amkeyward.TenantDefaultEnvironments,
                    ADD BLOCK PREDICATE amkeyward.fn_TenantAccessPredicate(TenantId) ON amkeyward.TenantDefaultEnvironments AFTER INSERT,
                    ADD BLOCK PREDICATE amkeyward.fn_TenantAccessPredicate(TenantId) ON amkeyward.TenantDefaultEnvironments AFTER UPDATE;");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(@"
                ALTER SECURITY POLICY amkeyward.TenantIsolationPolicy
                    DROP FILTER PREDICATE ON amkeyward.TenantDefaultEnvironments,
                    DROP BLOCK PREDICATE ON amkeyward.TenantDefaultEnvironments AFTER INSERT,
                    DROP BLOCK PREDICATE ON amkeyward.TenantDefaultEnvironments AFTER UPDATE;");

            migrationBuilder.DropTable(
                name: "TenantDefaultEnvironments",
                schema: "amkeyward");
        }
    }
}
