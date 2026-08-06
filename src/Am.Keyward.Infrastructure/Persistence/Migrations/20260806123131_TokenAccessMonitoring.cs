using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Am.Keyward.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class TokenAccessMonitoring : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "NotifyMonitoring",
                schema: "amkeyward",
                table: "Users",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.CreateTable(
                name: "TokenAccessMonitors",
                schema: "amkeyward",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TokenId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Enabled = table.Column<bool>(type: "bit", nullable: false),
                    MaxSilenceMinutes = table.Column<int>(type: "int", nullable: false),
                    WatchDaysMask = table.Column<byte>(type: "tinyint", nullable: false),
                    WatchStart = table.Column<TimeOnly>(type: "time", nullable: true),
                    WatchEnd = table.Column<TimeOnly>(type: "time", nullable: true),
                    NotifyOnRecovery = table.Column<bool>(type: "bit", nullable: false),
                    SnoozeUntil = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    State = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false),
                    LastStateChangeAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    LastEvaluatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TokenAccessMonitors", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TokenAccessMonitors_SoftwareClientTokens_TokenId",
                        column: x => x.TokenId,
                        principalSchema: "amkeyward",
                        principalTable: "SoftwareClientTokens",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_TokenAccessMonitors_TenantId",
                schema: "amkeyward",
                table: "TokenAccessMonitors",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_TokenAccessMonitors_TokenId",
                schema: "amkeyward",
                table: "TokenAccessMonitors",
                column: "TokenId",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "TokenAccessMonitors",
                schema: "amkeyward");

            migrationBuilder.DropColumn(
                name: "NotifyMonitoring",
                schema: "amkeyward",
                table: "Users");
        }
    }
}
