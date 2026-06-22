using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Am.Keyward.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class BreakGlass : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "BreakGlassGrants",
                schema: "amkeyward",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    ScopeKind = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false),
                    ScopeTargetId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    RequesterUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Reason = table.Column<string>(type: "nvarchar(1024)", maxLength: 1024, nullable: false),
                    Status = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false),
                    ApproverUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    RequestedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    DecidedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    ConsumedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_BreakGlassGrants", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_BreakGlassGrants_Status",
                schema: "amkeyward",
                table: "BreakGlassGrants",
                column: "Status");

            migrationBuilder.CreateIndex(
                name: "IX_BreakGlassGrants_TenantId",
                schema: "amkeyward",
                table: "BreakGlassGrants",
                column: "TenantId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "BreakGlassGrants",
                schema: "amkeyward");
        }
    }
}
