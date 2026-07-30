using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Am.Keyward.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class TokenAccessStatistics : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "NotifyTokenAccessAlerts",
                schema: "amkeyward",
                table: "Users",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "LastAccessAt",
                schema: "amkeyward",
                table: "SoftwareClientTokens",
                type: "datetimeoffset",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "LastAccessIp",
                schema: "amkeyward",
                table: "SoftwareClientTokens",
                type: "nvarchar(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.CreateTable(
                name: "TokenAccessAlerts",
                schema: "amkeyward",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TokenId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Kind = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    IpAddress = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    EmailedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TokenAccessAlerts", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TokenAccessAlerts_SoftwareClientTokens_TokenId",
                        column: x => x.TokenId,
                        principalSchema: "amkeyward",
                        principalTable: "SoftwareClientTokens",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "TokenAccessIps",
                schema: "amkeyward",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TokenId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    IpAddress = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    FirstSeenAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    LastSeenAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TokenAccessIps", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TokenAccessIps_SoftwareClientTokens_TokenId",
                        column: x => x.TokenId,
                        principalSchema: "amkeyward",
                        principalTable: "SoftwareClientTokens",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "TokenDailyAccesses",
                schema: "amkeyward",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TokenId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Date = table.Column<DateOnly>(type: "date", nullable: false),
                    RequestCount = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TokenDailyAccesses", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TokenDailyAccesses_SoftwareClientTokens_TokenId",
                        column: x => x.TokenId,
                        principalSchema: "amkeyward",
                        principalTable: "SoftwareClientTokens",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_TokenAccessAlerts_EmailedAt",
                schema: "amkeyward",
                table: "TokenAccessAlerts",
                column: "EmailedAt",
                filter: "[EmailedAt] IS NULL");

            migrationBuilder.CreateIndex(
                name: "IX_TokenAccessAlerts_TenantId",
                schema: "amkeyward",
                table: "TokenAccessAlerts",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_TokenAccessAlerts_TokenId_CreatedAt",
                schema: "amkeyward",
                table: "TokenAccessAlerts",
                columns: new[] { "TokenId", "CreatedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_TokenAccessIps_TenantId",
                schema: "amkeyward",
                table: "TokenAccessIps",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_TokenAccessIps_TokenId_IpAddress",
                schema: "amkeyward",
                table: "TokenAccessIps",
                columns: new[] { "TokenId", "IpAddress" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_TokenDailyAccesses_TenantId",
                schema: "amkeyward",
                table: "TokenDailyAccesses",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_TokenDailyAccesses_TokenId_Date",
                schema: "amkeyward",
                table: "TokenDailyAccesses",
                columns: new[] { "TokenId", "Date" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "TokenAccessAlerts",
                schema: "amkeyward");

            migrationBuilder.DropTable(
                name: "TokenAccessIps",
                schema: "amkeyward");

            migrationBuilder.DropTable(
                name: "TokenDailyAccesses",
                schema: "amkeyward");

            migrationBuilder.DropColumn(
                name: "NotifyTokenAccessAlerts",
                schema: "amkeyward",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "LastAccessAt",
                schema: "amkeyward",
                table: "SoftwareClientTokens");

            migrationBuilder.DropColumn(
                name: "LastAccessIp",
                schema: "amkeyward",
                table: "SoftwareClientTokens");
        }
    }
}
