using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Am.Keyward.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class InstallationRegistry : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Installations",
                schema: "amkeyward",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    InstallationKey = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: false),
                    MachineName = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                    EnvironmentName = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    ApplicationName = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    KekId = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                    KeyCustodyLocation = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: true),
                    SchemaVersion = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true),
                    FirstSeenAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    LastSeenAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Installations", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Installations_InstallationKey",
                schema: "amkeyward",
                table: "Installations",
                column: "InstallationKey",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Installations",
                schema: "amkeyward");
        }
    }
}
