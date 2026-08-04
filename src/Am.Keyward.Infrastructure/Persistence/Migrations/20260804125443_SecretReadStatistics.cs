using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Am.Keyward.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class SecretReadStatistics : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "SecretReadAccesses",
                schema: "amkeyward",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    SoftwareSecretId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    EnvironmentId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    LastReadAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    LastReadSource = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    ReadCount = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SecretReadAccesses", x => x.Id);
                    table.ForeignKey(
                        name: "FK_SecretReadAccesses_SoftwareSecrets_SoftwareSecretId",
                        column: x => x.SoftwareSecretId,
                        principalSchema: "amkeyward",
                        principalTable: "SoftwareSecrets",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_SecretReadAccesses_SoftwareSecretId_EnvironmentId",
                schema: "amkeyward",
                table: "SecretReadAccesses",
                columns: new[] { "SoftwareSecretId", "EnvironmentId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_SecretReadAccesses_TenantId",
                schema: "amkeyward",
                table: "SecretReadAccesses",
                column: "TenantId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "SecretReadAccesses",
                schema: "amkeyward");
        }
    }
}
