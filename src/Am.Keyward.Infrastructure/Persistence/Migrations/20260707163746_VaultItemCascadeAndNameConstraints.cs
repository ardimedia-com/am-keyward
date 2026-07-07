using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Am.Keyward.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class VaultItemCascadeAndNameConstraints : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Pre-existing data may violate the new constraints (duplicate names from before the
            // application-level uniqueness checks; orphaned items from before the vault FK existed).
            // Deduplicate by suffixing later duplicates, and remove orphaned item rows (their vault is
            // gone — they were unreachable ciphertext), so the index/FK creation cannot fail. Unique-index
            // and FK validation check ALL physical rows, so the row-level-security policy (which hides
            // everything from a connection without a tenant SESSION_CONTEXT — including the migrator) is
            // switched off around the data preparation.
            migrationBuilder.Sql(@"
                ALTER SECURITY POLICY amkeyward.TenantIsolationPolicy WITH (STATE = OFF);

                WITH d AS (SELECT Id, ROW_NUMBER() OVER (PARTITION BY TenantId, ProjectId, Name ORDER BY CreatedAt, Id) AS rn
                           FROM amkeyward.SoftwareClientTokens)
                UPDATE t SET t.Name = LEFT(t.Name, 200) + '-dup' + CAST(d.rn AS varchar(10))
                FROM amkeyward.SoftwareClientTokens t JOIN d ON d.Id = t.Id WHERE d.rn > 1;

                WITH d AS (SELECT Id, ROW_NUMBER() OVER (PARTITION BY TenantId, Name ORDER BY CreatedAt, Id) AS rn
                           FROM amkeyward.Projects)
                UPDATE p SET p.Name = LEFT(p.Name, 200) + '-dup' + CAST(d.rn AS varchar(10))
                FROM amkeyward.Projects p JOIN d ON d.Id = p.Id WHERE d.rn > 1;

                DELETE FROM amkeyward.VaultItemVersions
                WHERE VaultItemId IN (SELECT i.Id FROM amkeyward.VaultItems i
                                      WHERE NOT EXISTS (SELECT 1 FROM amkeyward.Vaults v WHERE v.Id = i.VaultId));
                DELETE FROM amkeyward.VaultItems
                WHERE NOT EXISTS (SELECT 1 FROM amkeyward.Vaults v WHERE v.Id = VaultId);

                ALTER SECURITY POLICY amkeyward.TenantIsolationPolicy WITH (STATE = ON);");

            migrationBuilder.CreateIndex(
                name: "IX_SoftwareClientTokens_TenantId_ProjectId_Name",
                schema: "amkeyward",
                table: "SoftwareClientTokens",
                columns: new[] { "TenantId", "ProjectId", "Name" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Projects_TenantId_Name",
                schema: "amkeyward",
                table: "Projects",
                columns: new[] { "TenantId", "Name" },
                unique: true);

            migrationBuilder.AddForeignKey(
                name: "FK_VaultItems_Vaults_VaultId",
                schema: "amkeyward",
                table: "VaultItems",
                column: "VaultId",
                principalSchema: "amkeyward",
                principalTable: "Vaults",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_VaultItems_Vaults_VaultId",
                schema: "amkeyward",
                table: "VaultItems");

            migrationBuilder.DropIndex(
                name: "IX_SoftwareClientTokens_TenantId_ProjectId_Name",
                schema: "amkeyward",
                table: "SoftwareClientTokens");

            migrationBuilder.DropIndex(
                name: "IX_Projects_TenantId_Name",
                schema: "amkeyward",
                table: "Projects");
        }
    }
}
