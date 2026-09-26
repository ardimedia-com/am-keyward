using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Am.Keyward.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class RevealRequests : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "RevealRequests",
                schema: "amkeyward",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TokenId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ItemId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Field = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false),
                    Reason = table.Column<string>(type: "nvarchar(500)", maxLength: 500, nullable: false),
                    Status = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    DecidedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    ConsumeBy = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    ConsumedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    RowVersion = table.Column<byte[]>(type: "rowversion", rowVersion: true, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RevealRequests", x => x.Id);
                    table.ForeignKey(
                        name: "FK_RevealRequests_AgentTokens_TokenId",
                        column: x => x.TokenId,
                        principalSchema: "amkeyward",
                        principalTable: "AgentTokens",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_RevealRequests_VaultItems_ItemId",
                        column: x => x.ItemId,
                        principalSchema: "amkeyward",
                        principalTable: "VaultItems",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_RevealRequests_ItemId",
                schema: "amkeyward",
                table: "RevealRequests",
                column: "ItemId");

            migrationBuilder.CreateIndex(
                name: "IX_RevealRequests_TenantId",
                schema: "amkeyward",
                table: "RevealRequests",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_RevealRequests_TokenId",
                schema: "amkeyward",
                table: "RevealRequests",
                column: "TokenId");

            migrationBuilder.CreateIndex(
                name: "IX_RevealRequests_UserId_Status",
                schema: "amkeyward",
                table: "RevealRequests",
                columns: new[] { "UserId", "Status" });

            // Row-level security: tenant content — same coverage as the other tenant-scoped tables (defense in
            // depth behind the EF query filter).
            migrationBuilder.Sql(@"
                ALTER SECURITY POLICY amkeyward.TenantIsolationPolicy
                    ADD FILTER PREDICATE amkeyward.fn_TenantAccessPredicate(TenantId) ON amkeyward.RevealRequests,
                    ADD BLOCK PREDICATE amkeyward.fn_TenantAccessPredicate(TenantId) ON amkeyward.RevealRequests AFTER INSERT,
                    ADD BLOCK PREDICATE amkeyward.fn_TenantAccessPredicate(TenantId) ON amkeyward.RevealRequests AFTER UPDATE;");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(@"
                ALTER SECURITY POLICY amkeyward.TenantIsolationPolicy
                    DROP FILTER PREDICATE ON amkeyward.RevealRequests,
                    DROP BLOCK PREDICATE ON amkeyward.RevealRequests AFTER INSERT,
                    DROP BLOCK PREDICATE ON amkeyward.RevealRequests AFTER UPDATE;");

            migrationBuilder.DropTable(
                name: "RevealRequests",
                schema: "amkeyward");
        }
    }
}
