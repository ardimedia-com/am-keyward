using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Am.Keyward.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class CryptoShredding : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "AuditSubjects",
                schema: "amkeyward",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    SubjectReference = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    EncryptedPii = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    ErasedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuditSubjects", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AuditSubjects_SubjectReference",
                schema: "amkeyward",
                table: "AuditSubjects",
                column: "SubjectReference");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AuditSubjects",
                schema: "amkeyward");
        }
    }
}
