using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Am.Keyward.Infrastructure.Persistence.Migrations
{
    /// <summary>
    /// Adds a trusted, server-side READ bypass to the row-level-security FILTER predicates of the three
    /// tables that legitimate maintenance code must read across tenant/owner scope:
    ///   - AuditEntries: the audit-chain writer must read a chain head whose tenant differs from the ambient
    ///     session tenant (a null/personal chain written while a tenant is in scope, or a cross-tenant
    ///     break-glass entry) — without the bypass the head read is filtered out and the chain silently forks;
    ///   - SecretVersions / VaultItemVersions: the KEK-integrity sweep must scan every stored envelope across
    ///     all tenants — without the bypass a tenant-less background scope sees zero rows and falsely reports
    ///     consistent.
    /// The bypass is honored ONLY by FILTER predicates (reads); the BLOCK predicates keep pointing at the
    /// original functions, so it can never enable a cross-tenant WRITE. It is keyed on
    /// SESSION_CONTEXT('SystemBypass') = 1, which is set only by the audit interceptor (around its head read)
    /// and by the ops-monitor / KEK-verifier sweeps — never on an ordinary request connection. The tables it
    /// exposes hold only ciphertext (secret/vault versions) and pseudonymized metadata (audit entries), never
    /// plaintext or key material.
    /// </summary>
    public partial class AuditSystemReadBypass : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Filter-only variants of the existing predicates, each OR'd with the system-read bypass.
            migrationBuilder.Sql(@"
                CREATE FUNCTION amkeyward.fn_AuditReadFilter(@TenantId uniqueidentifier)
                RETURNS TABLE WITH SCHEMABINDING
                AS RETURN
                    SELECT 1 AS fn_result
                    WHERE @TenantId = CAST(SESSION_CONTEXT(N'TenantId') AS uniqueidentifier)
                       OR (@TenantId IS NULL AND SESSION_CONTEXT(N'TenantId') IS NULL)
                       OR CAST(SESSION_CONTEXT(N'SystemBypass') AS bit) = 1;");

            migrationBuilder.Sql(@"
                CREATE FUNCTION amkeyward.fn_SecretVersionReadFilter(@TenantId uniqueidentifier)
                RETURNS TABLE WITH SCHEMABINDING
                AS RETURN
                    SELECT 1 AS fn_result
                    WHERE @TenantId = CAST(SESSION_CONTEXT(N'TenantId') AS uniqueidentifier)
                       OR CAST(SESSION_CONTEXT(N'SystemBypass') AS bit) = 1;");

            migrationBuilder.Sql(@"
                CREATE FUNCTION amkeyward.fn_VaultItemVersionReadFilter(@TenantId uniqueidentifier, @OwnerUserId uniqueidentifier)
                RETURNS TABLE WITH SCHEMABINDING
                AS RETURN
                    SELECT 1 AS fn_result
                    WHERE (@TenantId IS NOT NULL AND @TenantId = CAST(SESSION_CONTEXT(N'TenantId') AS uniqueidentifier))
                       OR (@TenantId IS NULL AND @OwnerUserId = CAST(SESSION_CONTEXT(N'UserId') AS uniqueidentifier))
                       OR CAST(SESSION_CONTEXT(N'SystemBypass') AS bit) = 1;");

            // Re-point ONLY the FILTER predicates on these three tables to the bypass-aware functions. The
            // BLOCK predicates on SecretVersions / VaultItemVersions stay on the original (non-bypass)
            // functions, so writes remain fully tenant-isolated. AuditEntries has no block predicate.
            // SQL Server rejects a DROP and ADD of the same table's filter predicate in one ALTER, so split.
            migrationBuilder.Sql(@"
                ALTER SECURITY POLICY amkeyward.TenantIsolationPolicy
                    DROP FILTER PREDICATE ON amkeyward.AuditEntries,
                    DROP FILTER PREDICATE ON amkeyward.SecretVersions,
                    DROP FILTER PREDICATE ON amkeyward.VaultItemVersions;");
            migrationBuilder.Sql(@"
                ALTER SECURITY POLICY amkeyward.TenantIsolationPolicy
                    ADD FILTER PREDICATE amkeyward.fn_AuditReadFilter(TenantId) ON amkeyward.AuditEntries,
                    ADD FILTER PREDICATE amkeyward.fn_SecretVersionReadFilter(TenantId) ON amkeyward.SecretVersions,
                    ADD FILTER PREDICATE amkeyward.fn_VaultItemVersionReadFilter(TenantId, OwnerUserId) ON amkeyward.VaultItemVersions;");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Restore the original filter predicates (no bypass) and drop the bypass-aware functions.
            migrationBuilder.Sql(@"
                ALTER SECURITY POLICY amkeyward.TenantIsolationPolicy
                    DROP FILTER PREDICATE ON amkeyward.AuditEntries,
                    DROP FILTER PREDICATE ON amkeyward.SecretVersions,
                    DROP FILTER PREDICATE ON amkeyward.VaultItemVersions;");
            migrationBuilder.Sql(@"
                ALTER SECURITY POLICY amkeyward.TenantIsolationPolicy
                    ADD FILTER PREDICATE amkeyward.fn_TenantAccessPredicateNullable(TenantId) ON amkeyward.AuditEntries,
                    ADD FILTER PREDICATE amkeyward.fn_TenantAccessPredicate(TenantId) ON amkeyward.SecretVersions,
                    ADD FILTER PREDICATE amkeyward.fn_VaultAccessPredicate(TenantId, OwnerUserId) ON amkeyward.VaultItemVersions;");

            migrationBuilder.Sql("DROP FUNCTION IF EXISTS amkeyward.fn_AuditReadFilter;");
            migrationBuilder.Sql("DROP FUNCTION IF EXISTS amkeyward.fn_SecretVersionReadFilter;");
            migrationBuilder.Sql("DROP FUNCTION IF EXISTS amkeyward.fn_VaultItemVersionReadFilter;");
        }
    }
}
