using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Am.Keyward.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class Groups : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "GroupMemberships",
                schema: "amkeyward",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    GroupId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Role = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_GroupMemberships", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "UserGroups",
                schema: "amkeyward",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UserGroups", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_GroupMemberships_GroupId_UserId",
                schema: "amkeyward",
                table: "GroupMemberships",
                columns: new[] { "GroupId", "UserId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_GroupMemberships_TenantId",
                schema: "amkeyward",
                table: "GroupMemberships",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_GroupMemberships_UserId",
                schema: "amkeyward",
                table: "GroupMemberships",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_UserGroups_TenantId_Name",
                schema: "amkeyward",
                table: "UserGroups",
                columns: new[] { "TenantId", "Name" },
                unique: true);

            // Row-level security: the group tables are tenant content — same coverage as the other
            // tenant-scoped tables (defense in depth behind the EF query filter).
            migrationBuilder.Sql(@"
                ALTER SECURITY POLICY amkeyward.TenantIsolationPolicy
                    ADD FILTER PREDICATE amkeyward.fn_TenantAccessPredicate(TenantId) ON amkeyward.UserGroups,
                    ADD BLOCK PREDICATE amkeyward.fn_TenantAccessPredicate(TenantId) ON amkeyward.UserGroups AFTER INSERT,
                    ADD BLOCK PREDICATE amkeyward.fn_TenantAccessPredicate(TenantId) ON amkeyward.UserGroups AFTER UPDATE,
                    ADD FILTER PREDICATE amkeyward.fn_TenantAccessPredicate(TenantId) ON amkeyward.GroupMemberships,
                    ADD BLOCK PREDICATE amkeyward.fn_TenantAccessPredicate(TenantId) ON amkeyward.GroupMemberships AFTER INSERT,
                    ADD BLOCK PREDICATE amkeyward.fn_TenantAccessPredicate(TenantId) ON amkeyward.GroupMemberships AFTER UPDATE;");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(@"
                ALTER SECURITY POLICY amkeyward.TenantIsolationPolicy
                    DROP FILTER PREDICATE ON amkeyward.UserGroups,
                    DROP BLOCK PREDICATE ON amkeyward.UserGroups AFTER INSERT,
                    DROP BLOCK PREDICATE ON amkeyward.UserGroups AFTER UPDATE,
                    DROP FILTER PREDICATE ON amkeyward.GroupMemberships,
                    DROP BLOCK PREDICATE ON amkeyward.GroupMemberships AFTER INSERT,
                    DROP BLOCK PREDICATE ON amkeyward.GroupMemberships AFTER UPDATE;");

            migrationBuilder.DropTable(
                name: "GroupMemberships",
                schema: "amkeyward");

            migrationBuilder.DropTable(
                name: "UserGroups",
                schema: "amkeyward");
        }
    }
}
