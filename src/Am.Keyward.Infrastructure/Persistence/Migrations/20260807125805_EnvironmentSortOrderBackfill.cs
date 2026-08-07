using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Am.Keyward.Infrastructure.Persistence.Migrations
{
    /// <summary>
    /// Repeats the SortOrder backfill of <c>20260806122206_EnvironmentSortOrder</c>, which silently did
    /// nothing.
    /// <para>
    /// That migration tried to escape the tenant-isolation RLS policy with
    /// <c>sp_set_session_context @key = N'SystemBypass'</c>. The bypass exists only in the audit /
    /// encrypted-version predicates — <c>fn_TenantAccessPredicate</c>, which guards RuntimeEnvironments and
    /// TenantDefaultEnvironments, is plain <c>@TenantId = CAST(SESSION_CONTEXT(N'TenantId') AS
    /// uniqueidentifier)</c>. A migration connection carries no TenantId, so the predicate is never true, both
    /// UPDATEs matched zero rows, and every SortOrder stayed 0 — leaving the display order to the
    /// tie-break by name (Development, Production, Test instead of Development, Test, Production).
    /// An UPDATE that matches nothing is not an error, so the migration reported success.
    /// </para>
    /// <para>
    /// This one uses the pattern that already works in <c>20260721100701_VaultItemPublicId</c> and
    /// <c>20260707163746_VaultItemCascadeAndNameConstraints</c>: switch the security policy off for the
    /// backfill and back on afterwards. It needs ALTER ANY SECURITY POLICY, i.e. the same privileged
    /// connection those two already require (see db/keyward-provisioning.md); the guard makes it a harmless
    /// no-op when the policy is not present yet.
    /// </para>
    /// <para>Idempotent: it only ranks rows whose SortOrder is still all-zero within their partition, so an
    /// installation that already has a deliberate order is left alone.</para>
    /// </summary>
    public partial class EnvironmentSortOrderBackfill : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("""
                IF EXISTS (SELECT 1 FROM sys.security_policies sp JOIN sys.schemas s ON s.schema_id = sp.schema_id
                           WHERE sp.name = 'TenantIsolationPolicy' AND s.name = 'amkeyward')
                    ALTER SECURITY POLICY amkeyward.TenantIsolationPolicy WITH (STATE = OFF);
                """);

            migrationBuilder.Sql("""
                WITH RankedEnvironments AS (
                    SELECT SortOrder,
                           ROW_NUMBER() OVER (
                               PARTITION BY ProjectId
                               ORDER BY CASE Name
                                            WHEN 'Development' THEN 0
                                            WHEN 'Test' THEN 1
                                            WHEN 'Production' THEN 2
                                            ELSE 3
                                        END, Name) - 1 AS NewOrder,
                           MAX(SortOrder) OVER (PARTITION BY ProjectId) AS MaxOrder
                    FROM [amkeyward].[RuntimeEnvironments]
                )
                UPDATE RankedEnvironments SET SortOrder = NewOrder WHERE MaxOrder = 0;

                WITH RankedDefaults AS (
                    SELECT SortOrder,
                           ROW_NUMBER() OVER (
                               PARTITION BY TenantId
                               ORDER BY CASE Name
                                            WHEN 'Development' THEN 0
                                            WHEN 'Test' THEN 1
                                            WHEN 'Production' THEN 2
                                            ELSE 3
                                        END, Name) - 1 AS NewOrder,
                           MAX(SortOrder) OVER (PARTITION BY TenantId) AS MaxOrder
                    FROM [amkeyward].[TenantDefaultEnvironments]
                )
                UPDATE RankedDefaults SET SortOrder = NewOrder WHERE MaxOrder = 0;
                """);

            migrationBuilder.Sql("""
                IF EXISTS (SELECT 1 FROM sys.security_policies sp JOIN sys.schemas s ON s.schema_id = sp.schema_id
                           WHERE sp.name = 'TenantIsolationPolicy' AND s.name = 'amkeyward')
                    ALTER SECURITY POLICY amkeyward.TenantIsolationPolicy WITH (STATE = ON);
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Nothing to undo: the column and its values already existed before this migration — it only
            // corrects data the previous migration failed to write.
        }
    }
}
