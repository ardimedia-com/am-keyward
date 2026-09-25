using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Am.Keyward.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AuditActorKind : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "ActorKind",
                schema: "amkeyward",
                table: "AuditEntries",
                type: "nvarchar(16)",
                maxLength: 16,
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "ActorTokenId",
                schema: "amkeyward",
                table: "AuditEntries",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "HashVersion",
                schema: "amkeyward",
                table: "AuditEntries",
                type: "int",
                nullable: false,
                // Every existing row was sealed with the original canonical form, i.e. hash version 1.
                defaultValue: 1);

            migrationBuilder.AddColumn<string>(
                name: "Reason",
                schema: "amkeyward",
                table: "AuditEntries",
                type: "nvarchar(500)",
                maxLength: 500,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ActorKind",
                schema: "amkeyward",
                table: "AuditEntries");

            migrationBuilder.DropColumn(
                name: "ActorTokenId",
                schema: "amkeyward",
                table: "AuditEntries");

            migrationBuilder.DropColumn(
                name: "HashVersion",
                schema: "amkeyward",
                table: "AuditEntries");

            migrationBuilder.DropColumn(
                name: "Reason",
                schema: "amkeyward",
                table: "AuditEntries");
        }
    }
}
