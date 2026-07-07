using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Am.Keyward.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class FolderHierarchy : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "ParentFolderId",
                schema: "amkeyward",
                table: "Folders",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_Folders_ParentFolderId",
                schema: "amkeyward",
                table: "Folders",
                column: "ParentFolderId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Folders_ParentFolderId",
                schema: "amkeyward",
                table: "Folders");

            migrationBuilder.DropColumn(
                name: "ParentFolderId",
                schema: "amkeyward",
                table: "Folders");
        }
    }
}
