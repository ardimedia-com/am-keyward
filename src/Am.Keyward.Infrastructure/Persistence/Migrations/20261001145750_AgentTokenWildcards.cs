using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Am.Keyward.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AgentTokenWildcards : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "AllAgentVaults",
                schema: "amkeyward",
                table: "AgentTokens",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<bool>(
                name: "AllApplications",
                schema: "amkeyward",
                table: "AgentTokens",
                type: "bit",
                nullable: false,
                defaultValue: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "AllAgentVaults",
                schema: "amkeyward",
                table: "AgentTokens");

            migrationBuilder.DropColumn(
                name: "AllApplications",
                schema: "amkeyward",
                table: "AgentTokens");
        }
    }
}
