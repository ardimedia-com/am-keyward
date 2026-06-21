using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Am.Keyward.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class HumanVaults : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "VaultItems",
                schema: "amkeyward",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    VaultId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    OwnerUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    FolderId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    Type = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    Name = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    CreatedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    CurrentVersionId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_VaultItems", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Vaults",
                schema: "amkeyward",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    OwnerType = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false),
                    OwnerId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    OwnerUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    ProtectionMode = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false),
                    Name = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Vaults", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "VaultItemVersions",
                schema: "amkeyward",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    VaultItemId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    OwnerUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    VersionNumber = table.Column<int>(type: "int", nullable: false),
                    Encrypted = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_VaultItemVersions", x => x.Id);
                    table.ForeignKey(
                        name: "FK_VaultItemVersions_VaultItems_VaultItemId",
                        column: x => x.VaultItemId,
                        principalSchema: "amkeyward",
                        principalTable: "VaultItems",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Folders",
                schema: "amkeyward",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    VaultId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    OwnerUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    Name = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Folders", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Folders_Vaults_VaultId",
                        column: x => x.VaultId,
                        principalSchema: "amkeyward",
                        principalTable: "Vaults",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Folders_OwnerUserId",
                schema: "amkeyward",
                table: "Folders",
                column: "OwnerUserId");

            migrationBuilder.CreateIndex(
                name: "IX_Folders_TenantId",
                schema: "amkeyward",
                table: "Folders",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_Folders_VaultId",
                schema: "amkeyward",
                table: "Folders",
                column: "VaultId");

            migrationBuilder.CreateIndex(
                name: "IX_VaultItems_FolderId",
                schema: "amkeyward",
                table: "VaultItems",
                column: "FolderId");

            migrationBuilder.CreateIndex(
                name: "IX_VaultItems_OwnerUserId",
                schema: "amkeyward",
                table: "VaultItems",
                column: "OwnerUserId");

            migrationBuilder.CreateIndex(
                name: "IX_VaultItems_TenantId",
                schema: "amkeyward",
                table: "VaultItems",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_VaultItems_VaultId",
                schema: "amkeyward",
                table: "VaultItems",
                column: "VaultId");

            migrationBuilder.CreateIndex(
                name: "IX_VaultItemVersions_OwnerUserId",
                schema: "amkeyward",
                table: "VaultItemVersions",
                column: "OwnerUserId");

            migrationBuilder.CreateIndex(
                name: "IX_VaultItemVersions_TenantId",
                schema: "amkeyward",
                table: "VaultItemVersions",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_VaultItemVersions_VaultItemId_VersionNumber",
                schema: "amkeyward",
                table: "VaultItemVersions",
                columns: new[] { "VaultItemId", "VersionNumber" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Vaults_OwnerUserId",
                schema: "amkeyward",
                table: "Vaults",
                column: "OwnerUserId");

            migrationBuilder.CreateIndex(
                name: "IX_Vaults_TenantId",
                schema: "amkeyward",
                table: "Vaults",
                column: "TenantId");

            // Row-level security for vaults: tenant vaults are admitted by SESSION_CONTEXT('TenantId');
            // personal (tenant-less) vaults by SESSION_CONTEXT('UserId'). Extends the existing policy.
            migrationBuilder.Sql(@"
                CREATE FUNCTION amkeyward.fn_VaultAccessPredicate(@TenantId uniqueidentifier, @OwnerUserId uniqueidentifier)
                RETURNS TABLE WITH SCHEMABINDING
                AS RETURN
                    SELECT 1 AS fn_result
                    WHERE (@TenantId IS NOT NULL AND @TenantId = CAST(SESSION_CONTEXT(N'TenantId') AS uniqueidentifier))
                       OR (@TenantId IS NULL AND @OwnerUserId = CAST(SESSION_CONTEXT(N'UserId') AS uniqueidentifier));");

            migrationBuilder.Sql(@"
                ALTER SECURITY POLICY amkeyward.TenantIsolationPolicy
                    ADD FILTER PREDICATE amkeyward.fn_VaultAccessPredicate(TenantId, OwnerUserId) ON amkeyward.Vaults,
                    ADD BLOCK PREDICATE amkeyward.fn_VaultAccessPredicate(TenantId, OwnerUserId) ON amkeyward.Vaults AFTER INSERT,
                    ADD BLOCK PREDICATE amkeyward.fn_VaultAccessPredicate(TenantId, OwnerUserId) ON amkeyward.Vaults AFTER UPDATE,
                    ADD FILTER PREDICATE amkeyward.fn_VaultAccessPredicate(TenantId, OwnerUserId) ON amkeyward.Folders,
                    ADD BLOCK PREDICATE amkeyward.fn_VaultAccessPredicate(TenantId, OwnerUserId) ON amkeyward.Folders AFTER INSERT,
                    ADD BLOCK PREDICATE amkeyward.fn_VaultAccessPredicate(TenantId, OwnerUserId) ON amkeyward.Folders AFTER UPDATE,
                    ADD FILTER PREDICATE amkeyward.fn_VaultAccessPredicate(TenantId, OwnerUserId) ON amkeyward.VaultItems,
                    ADD BLOCK PREDICATE amkeyward.fn_VaultAccessPredicate(TenantId, OwnerUserId) ON amkeyward.VaultItems AFTER INSERT,
                    ADD BLOCK PREDICATE amkeyward.fn_VaultAccessPredicate(TenantId, OwnerUserId) ON amkeyward.VaultItems AFTER UPDATE,
                    ADD FILTER PREDICATE amkeyward.fn_VaultAccessPredicate(TenantId, OwnerUserId) ON amkeyward.VaultItemVersions,
                    ADD BLOCK PREDICATE amkeyward.fn_VaultAccessPredicate(TenantId, OwnerUserId) ON amkeyward.VaultItemVersions AFTER INSERT,
                    ADD BLOCK PREDICATE amkeyward.fn_VaultAccessPredicate(TenantId, OwnerUserId) ON amkeyward.VaultItemVersions AFTER UPDATE;");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(@"
                ALTER SECURITY POLICY amkeyward.TenantIsolationPolicy
                    DROP FILTER PREDICATE ON amkeyward.Vaults,
                    DROP BLOCK PREDICATE ON amkeyward.Vaults AFTER INSERT,
                    DROP BLOCK PREDICATE ON amkeyward.Vaults AFTER UPDATE,
                    DROP FILTER PREDICATE ON amkeyward.Folders,
                    DROP BLOCK PREDICATE ON amkeyward.Folders AFTER INSERT,
                    DROP BLOCK PREDICATE ON amkeyward.Folders AFTER UPDATE,
                    DROP FILTER PREDICATE ON amkeyward.VaultItems,
                    DROP BLOCK PREDICATE ON amkeyward.VaultItems AFTER INSERT,
                    DROP BLOCK PREDICATE ON amkeyward.VaultItems AFTER UPDATE,
                    DROP FILTER PREDICATE ON amkeyward.VaultItemVersions,
                    DROP BLOCK PREDICATE ON amkeyward.VaultItemVersions AFTER INSERT,
                    DROP BLOCK PREDICATE ON amkeyward.VaultItemVersions AFTER UPDATE;");
            migrationBuilder.Sql("DROP FUNCTION IF EXISTS amkeyward.fn_VaultAccessPredicate;");

            migrationBuilder.DropTable(
                name: "Folders",
                schema: "amkeyward");

            migrationBuilder.DropTable(
                name: "VaultItemVersions",
                schema: "amkeyward");

            migrationBuilder.DropTable(
                name: "Vaults",
                schema: "amkeyward");

            migrationBuilder.DropTable(
                name: "VaultItems",
                schema: "amkeyward");
        }
    }
}
