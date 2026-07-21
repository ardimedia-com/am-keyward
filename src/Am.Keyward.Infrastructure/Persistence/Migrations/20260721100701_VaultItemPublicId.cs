using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Am.Keyward.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class VaultItemPublicId : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "PublicId",
                schema: "amkeyward",
                table: "VaultItems",
                type: "uniqueidentifier",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            // Existing rows all landed on the empty-GUID default; give each a distinct value BEFORE the unique
            // index is created, otherwise it would collide. Random per row = a stable public deep-link id.
            migrationBuilder.Sql("UPDATE amkeyward.VaultItems SET PublicId = NEWID();");

            migrationBuilder.CreateIndex(
                name: "IX_VaultItems_PublicId",
                schema: "amkeyward",
                table: "VaultItems",
                column: "PublicId",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_VaultItems_PublicId",
                schema: "amkeyward",
                table: "VaultItems");

            migrationBuilder.DropColumn(
                name: "PublicId",
                schema: "amkeyward",
                table: "VaultItems");
        }
    }
}
