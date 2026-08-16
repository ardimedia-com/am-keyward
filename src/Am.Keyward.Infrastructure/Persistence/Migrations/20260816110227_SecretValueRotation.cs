using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Am.Keyward.Infrastructure.Persistence.Migrations
{
    /// <summary>
    /// Rotation metadata per (secret, environment): an advisory <c>ExpiresAt</c> (it never blocks a read —
    /// a forgotten rotation must not take a deployed application down), a free-text <c>Note</c> describing
    /// how a new value is obtained, and <c>LastExpiryNoticeDaysLeft</c> as the notice dedupe state (mirrors
    /// the app-token columns). The filtered index serves the hourly expiry sweep, which would otherwise scan
    /// the whole table.
    /// <para>
    /// Also renames <c>Users.NotifyTokenExpiry</c> to <c>NotifyExpiry</c>: the opt-in now covers both app
    /// tokens and secret values, and a rename (not a new column) keeps everyone's existing choice.
    /// </para>
    /// </summary>
    public partial class SecretValueRotation : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "NotifyTokenExpiry",
                schema: "amkeyward",
                table: "Users",
                newName: "NotifyExpiry");

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "ExpiresAt",
                schema: "amkeyward",
                table: "SecretValues",
                type: "datetimeoffset",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "LastExpiryNoticeDaysLeft",
                schema: "amkeyward",
                table: "SecretValues",
                type: "int",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Note",
                schema: "amkeyward",
                table: "SecretValues",
                type: "nvarchar(1024)",
                maxLength: 1024,
                nullable: false,
                defaultValue: "");

            migrationBuilder.CreateIndex(
                name: "IX_SecretValues_ExpiresAt",
                schema: "amkeyward",
                table: "SecretValues",
                column: "ExpiresAt",
                filter: "[ExpiresAt] IS NOT NULL");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_SecretValues_ExpiresAt",
                schema: "amkeyward",
                table: "SecretValues");

            migrationBuilder.DropColumn(
                name: "ExpiresAt",
                schema: "amkeyward",
                table: "SecretValues");

            migrationBuilder.DropColumn(
                name: "LastExpiryNoticeDaysLeft",
                schema: "amkeyward",
                table: "SecretValues");

            migrationBuilder.DropColumn(
                name: "Note",
                schema: "amkeyward",
                table: "SecretValues");

            migrationBuilder.RenameColumn(
                name: "NotifyExpiry",
                schema: "amkeyward",
                table: "Users",
                newName: "NotifyTokenExpiry");
        }
    }
}
