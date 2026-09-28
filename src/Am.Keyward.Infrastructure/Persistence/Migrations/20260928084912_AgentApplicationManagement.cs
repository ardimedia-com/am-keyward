using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Am.Keyward.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AgentApplicationManagement : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "CreatedByAgentTokenId",
                schema: "amkeyward",
                table: "SoftwareSecrets",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "CreatedByAgentTokenId",
                schema: "amkeyward",
                table: "Projects",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "MayCreateApplications",
                schema: "amkeyward",
                table: "AgentTokens",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.CreateTable(
                name: "AgentTokenApplicationAllowances",
                schema: "amkeyward",
                columns: table => new
                {
                    TokenId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ProjectId = table.Column<Guid>(type: "uniqueidentifier", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AgentTokenApplicationAllowances", x => new { x.TokenId, x.ProjectId });
                    table.ForeignKey(
                        name: "FK_AgentTokenApplicationAllowances_AgentTokens_TokenId",
                        column: x => x.TokenId,
                        principalSchema: "amkeyward",
                        principalTable: "AgentTokens",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_AgentTokenApplicationAllowances_Projects_ProjectId",
                        column: x => x.ProjectId,
                        principalSchema: "amkeyward",
                        principalTable: "Projects",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AgentTokenApplicationAllowances_ProjectId",
                schema: "amkeyward",
                table: "AgentTokenApplicationAllowances",
                column: "ProjectId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AgentTokenApplicationAllowances",
                schema: "amkeyward");

            migrationBuilder.DropColumn(
                name: "CreatedByAgentTokenId",
                schema: "amkeyward",
                table: "SoftwareSecrets");

            migrationBuilder.DropColumn(
                name: "CreatedByAgentTokenId",
                schema: "amkeyward",
                table: "Projects");

            migrationBuilder.DropColumn(
                name: "MayCreateApplications",
                schema: "amkeyward",
                table: "AgentTokens");
        }
    }
}
