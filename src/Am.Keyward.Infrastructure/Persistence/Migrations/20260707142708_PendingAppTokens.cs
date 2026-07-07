using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Am.Keyward.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class PendingAppTokens : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_SoftwareClientTokens_TokenPrefix",
                schema: "amkeyward",
                table: "SoftwareClientTokens");

            migrationBuilder.CreateIndex(
                name: "IX_SoftwareClientTokens_TokenPrefix",
                schema: "amkeyward",
                table: "SoftwareClientTokens",
                column: "TokenPrefix",
                unique: true,
                filter: "[TokenPrefix] <> ''");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_SoftwareClientTokens_TokenPrefix",
                schema: "amkeyward",
                table: "SoftwareClientTokens");

            // Pending placeholders (empty prefix) would violate the unfiltered unique index this Down
            // restores — remove them first, or the rollback itself fails.
            migrationBuilder.Sql("DELETE FROM amkeyward.SoftwareClientTokens WHERE TokenPrefix = '';");

            migrationBuilder.CreateIndex(
                name: "IX_SoftwareClientTokens_TokenPrefix",
                schema: "amkeyward",
                table: "SoftwareClientTokens",
                column: "TokenPrefix",
                unique: true);
        }
    }
}
