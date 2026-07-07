using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Am.Keyward.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class TokenExpiryNotifications : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "NotifyTokenExpiry",
                schema: "amkeyward",
                table: "Users",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<int>(
                name: "LastExpiryNoticeDaysLeft",
                schema: "amkeyward",
                table: "SoftwareClientTokens",
                type: "int",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "NotifyTokenExpiry",
                schema: "amkeyward",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "LastExpiryNoticeDaysLeft",
                schema: "amkeyward",
                table: "SoftwareClientTokens");
        }
    }
}
