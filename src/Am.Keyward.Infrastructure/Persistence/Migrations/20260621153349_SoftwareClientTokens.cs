using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Am.Keyward.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class SoftwareClientTokens : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "SoftwareClientTokens",
                schema: "amkeyward",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ProjectId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    EnvironmentId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    TokenPrefix = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    TokenHash = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                    CreatedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    LastRotatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    RevokedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SoftwareClientTokens", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_SoftwareClientTokens_TenantId_ProjectId",
                schema: "amkeyward",
                table: "SoftwareClientTokens",
                columns: new[] { "TenantId", "ProjectId" });

            migrationBuilder.CreateIndex(
                name: "IX_SoftwareClientTokens_TokenPrefix",
                schema: "amkeyward",
                table: "SoftwareClientTokens",
                column: "TokenPrefix",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "SoftwareClientTokens",
                schema: "amkeyward");
        }
    }
}
