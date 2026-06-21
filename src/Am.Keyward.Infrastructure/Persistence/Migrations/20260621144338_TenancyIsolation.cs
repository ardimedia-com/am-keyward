using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Am.Keyward.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class TenancyIsolation : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // 1) Add the denormalized TenantId columns as nullable so existing rows can be backfilled.
            migrationBuilder.AddColumn<Guid>(name: "TenantId", schema: "amkeyward", table: "SoftwareSecrets", type: "uniqueidentifier", nullable: true);
            migrationBuilder.AddColumn<Guid>(name: "TenantId", schema: "amkeyward", table: "SecretValues", type: "uniqueidentifier", nullable: true);
            migrationBuilder.AddColumn<Guid>(name: "TenantId", schema: "amkeyward", table: "SecretVersions", type: "uniqueidentifier", nullable: true);
            migrationBuilder.AddColumn<Guid>(name: "TenantId", schema: "amkeyward", table: "RuntimeEnvironments", type: "uniqueidentifier", nullable: true);

            // 2) Backfill each table's tenant from its parent chain (Projects is already tenant-stamped).
            migrationBuilder.Sql(@"
                UPDATE e SET e.TenantId = p.TenantId
                FROM amkeyward.RuntimeEnvironments e
                INNER JOIN amkeyward.Projects p ON p.Id = e.ProjectId;");
            migrationBuilder.Sql(@"
                UPDATE s SET s.TenantId = p.TenantId
                FROM amkeyward.SoftwareSecrets s
                INNER JOIN amkeyward.Projects p ON p.Id = s.ProjectId;");
            migrationBuilder.Sql(@"
                UPDATE v SET v.TenantId = s.TenantId
                FROM amkeyward.SecretValues v
                INNER JOIN amkeyward.SoftwareSecrets s ON s.Id = v.SoftwareSecretId;");
            migrationBuilder.Sql(@"
                UPDATE ver SET ver.TenantId = v.TenantId
                FROM amkeyward.SecretVersions ver
                INNER JOIN amkeyward.SecretValues v ON v.Id = ver.SecretValueId;");

            // 3) Now that every row has a tenant, make the columns required.
            migrationBuilder.AlterColumn<Guid>(name: "TenantId", schema: "amkeyward", table: "SoftwareSecrets", type: "uniqueidentifier", nullable: false, oldClrType: typeof(Guid), oldType: "uniqueidentifier", oldNullable: true);
            migrationBuilder.AlterColumn<Guid>(name: "TenantId", schema: "amkeyward", table: "SecretValues", type: "uniqueidentifier", nullable: false, oldClrType: typeof(Guid), oldType: "uniqueidentifier", oldNullable: true);
            migrationBuilder.AlterColumn<Guid>(name: "TenantId", schema: "amkeyward", table: "SecretVersions", type: "uniqueidentifier", nullable: false, oldClrType: typeof(Guid), oldType: "uniqueidentifier", oldNullable: true);
            migrationBuilder.AlterColumn<Guid>(name: "TenantId", schema: "amkeyward", table: "RuntimeEnvironments", type: "uniqueidentifier", nullable: false, oldClrType: typeof(Guid), oldType: "uniqueidentifier", oldNullable: true);

            // 4) Indexes supporting the tenant query filter and the row-level-security predicates.
            migrationBuilder.CreateIndex(name: "IX_SoftwareSecrets_TenantId", schema: "amkeyward", table: "SoftwareSecrets", column: "TenantId");
            migrationBuilder.CreateIndex(name: "IX_SecretVersions_TenantId", schema: "amkeyward", table: "SecretVersions", column: "TenantId");
            migrationBuilder.CreateIndex(name: "IX_SecretValues_TenantId", schema: "amkeyward", table: "SecretValues", column: "TenantId");
            migrationBuilder.CreateIndex(name: "IX_RuntimeEnvironments_TenantId", schema: "amkeyward", table: "RuntimeEnvironments", column: "TenantId");
            migrationBuilder.CreateIndex(name: "IX_Projects_TenantId", schema: "amkeyward", table: "Projects", column: "TenantId");

            // 5) Row-level security: a schemabound predicate that admits a row only when its tenant equals
            //    the connection's SESSION_CONTEXT('TenantId'). This is the database-level backstop to the
            //    application tenant query filter (see TenantSessionContextInterceptor). Each CREATE FUNCTION
            //    must be the first statement in its batch, so it gets its own Sql() call.
            migrationBuilder.Sql(@"
                CREATE FUNCTION amkeyward.fn_TenantAccessPredicate(@TenantId uniqueidentifier)
                RETURNS TABLE WITH SCHEMABINDING
                AS RETURN
                    SELECT 1 AS fn_result
                    WHERE @TenantId = CAST(SESSION_CONTEXT(N'TenantId') AS uniqueidentifier);");

            // AuditEntries also keeps system-level rows (null tenant), visible only when no tenant is in scope.
            migrationBuilder.Sql(@"
                CREATE FUNCTION amkeyward.fn_TenantAccessPredicateNullable(@TenantId uniqueidentifier)
                RETURNS TABLE WITH SCHEMABINDING
                AS RETURN
                    SELECT 1 AS fn_result
                    WHERE @TenantId = CAST(SESSION_CONTEXT(N'TenantId') AS uniqueidentifier)
                       OR (@TenantId IS NULL AND SESSION_CONTEXT(N'TenantId') IS NULL);");

            migrationBuilder.Sql(@"
                CREATE SECURITY POLICY amkeyward.TenantIsolationPolicy
                    ADD FILTER PREDICATE amkeyward.fn_TenantAccessPredicate(Id) ON amkeyward.Tenants,
                    ADD BLOCK PREDICATE amkeyward.fn_TenantAccessPredicate(Id) ON amkeyward.Tenants AFTER INSERT,
                    ADD FILTER PREDICATE amkeyward.fn_TenantAccessPredicate(TenantId) ON amkeyward.Projects,
                    ADD BLOCK PREDICATE amkeyward.fn_TenantAccessPredicate(TenantId) ON amkeyward.Projects AFTER INSERT,
                    ADD BLOCK PREDICATE amkeyward.fn_TenantAccessPredicate(TenantId) ON amkeyward.Projects AFTER UPDATE,
                    ADD FILTER PREDICATE amkeyward.fn_TenantAccessPredicate(TenantId) ON amkeyward.RuntimeEnvironments,
                    ADD BLOCK PREDICATE amkeyward.fn_TenantAccessPredicate(TenantId) ON amkeyward.RuntimeEnvironments AFTER INSERT,
                    ADD BLOCK PREDICATE amkeyward.fn_TenantAccessPredicate(TenantId) ON amkeyward.RuntimeEnvironments AFTER UPDATE,
                    ADD FILTER PREDICATE amkeyward.fn_TenantAccessPredicate(TenantId) ON amkeyward.SoftwareSecrets,
                    ADD BLOCK PREDICATE amkeyward.fn_TenantAccessPredicate(TenantId) ON amkeyward.SoftwareSecrets AFTER INSERT,
                    ADD BLOCK PREDICATE amkeyward.fn_TenantAccessPredicate(TenantId) ON amkeyward.SoftwareSecrets AFTER UPDATE,
                    ADD FILTER PREDICATE amkeyward.fn_TenantAccessPredicate(TenantId) ON amkeyward.SecretValues,
                    ADD BLOCK PREDICATE amkeyward.fn_TenantAccessPredicate(TenantId) ON amkeyward.SecretValues AFTER INSERT,
                    ADD BLOCK PREDICATE amkeyward.fn_TenantAccessPredicate(TenantId) ON amkeyward.SecretValues AFTER UPDATE,
                    ADD FILTER PREDICATE amkeyward.fn_TenantAccessPredicate(TenantId) ON amkeyward.SecretVersions,
                    ADD BLOCK PREDICATE amkeyward.fn_TenantAccessPredicate(TenantId) ON amkeyward.SecretVersions AFTER INSERT,
                    ADD BLOCK PREDICATE amkeyward.fn_TenantAccessPredicate(TenantId) ON amkeyward.SecretVersions AFTER UPDATE,
                    ADD FILTER PREDICATE amkeyward.fn_TenantAccessPredicateNullable(TenantId) ON amkeyward.AuditEntries
                    WITH (STATE = ON);");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("DROP SECURITY POLICY IF EXISTS amkeyward.TenantIsolationPolicy;");
            migrationBuilder.Sql("DROP FUNCTION IF EXISTS amkeyward.fn_TenantAccessPredicate;");
            migrationBuilder.Sql("DROP FUNCTION IF EXISTS amkeyward.fn_TenantAccessPredicateNullable;");

            migrationBuilder.DropIndex(name: "IX_SoftwareSecrets_TenantId", schema: "amkeyward", table: "SoftwareSecrets");
            migrationBuilder.DropIndex(name: "IX_SecretVersions_TenantId", schema: "amkeyward", table: "SecretVersions");
            migrationBuilder.DropIndex(name: "IX_SecretValues_TenantId", schema: "amkeyward", table: "SecretValues");
            migrationBuilder.DropIndex(name: "IX_RuntimeEnvironments_TenantId", schema: "amkeyward", table: "RuntimeEnvironments");
            migrationBuilder.DropIndex(name: "IX_Projects_TenantId", schema: "amkeyward", table: "Projects");

            migrationBuilder.DropColumn(name: "TenantId", schema: "amkeyward", table: "SoftwareSecrets");
            migrationBuilder.DropColumn(name: "TenantId", schema: "amkeyward", table: "SecretValues");
            migrationBuilder.DropColumn(name: "TenantId", schema: "amkeyward", table: "SecretVersions");
            migrationBuilder.DropColumn(name: "TenantId", schema: "amkeyward", table: "RuntimeEnvironments");
        }
    }
}
