using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Am.Keyward.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AgentTokens : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "AgentAccessAllowed",
                schema: "amkeyward",
                table: "Vaults",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.CreateTable(
                name: "AgentTokens",
                schema: "amkeyward",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    TokenPrefix = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    TokenHash = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                    Scopes = table.Column<int>(type: "int", nullable: false),
                    AllowedNetworks = table.Column<string>(type: "nvarchar(1024)", maxLength: 1024, nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    LastRotatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    RevokedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AgentTokens", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AgentTokenVaultAllowances",
                schema: "amkeyward",
                columns: table => new
                {
                    TokenId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    VaultId = table.Column<Guid>(type: "uniqueidentifier", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AgentTokenVaultAllowances", x => new { x.TokenId, x.VaultId });
                    table.ForeignKey(
                        name: "FK_AgentTokenVaultAllowances_AgentTokens_TokenId",
                        column: x => x.TokenId,
                        principalSchema: "amkeyward",
                        principalTable: "AgentTokens",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_AgentTokenVaultAllowances_Vaults_VaultId",
                        column: x => x.VaultId,
                        principalSchema: "amkeyward",
                        principalTable: "Vaults",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AgentTokens_TenantId_UserId",
                schema: "amkeyward",
                table: "AgentTokens",
                columns: new[] { "TenantId", "UserId" });

            migrationBuilder.CreateIndex(
                name: "IX_AgentTokens_TokenPrefix",
                schema: "amkeyward",
                table: "AgentTokens",
                column: "TokenPrefix",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AgentTokenVaultAllowances_VaultId",
                schema: "amkeyward",
                table: "AgentTokenVaultAllowances",
                column: "VaultId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AgentTokenVaultAllowances",
                schema: "amkeyward");

            migrationBuilder.DropTable(
                name: "AgentTokens",
                schema: "amkeyward");

            migrationBuilder.DropColumn(
                name: "AgentAccessAllowed",
                schema: "amkeyward",
                table: "Vaults");
        }
    }
}
