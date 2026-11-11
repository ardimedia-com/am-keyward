using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Am.Keyward.Infrastructure.Persistence.Migrations
{
    /// <summary>
    /// Review 3, area «vaults, persistence, schema»:
    /// <list type="bullet">
    /// <item><c>VaultItems.Revision</c> (renewed on every change, the new concurrency token / ETag) and
    /// <c>LastVersionNumber</c> (persisted version counter), backfilled from the current version and the history;
    /// <c>RenamedByAgentTokenId</c> / <c>NameBeforeAgentRename</c> (an agent's rename stays visible).</item>
    /// <item><c>RevealRequests</c> snapshot the item name (and an agent's rename) and revision; existing rows are
    /// backfilled from the item.</item>
    /// <item><c>AgentTokens.LastUsedAt</c> / <c>LastUsedIp</c>; <c>Users.DeletedAt</c> (account deletion with
    /// retention).</item>
    /// <item>One grant per (principal, scope): duplicates are reduced to the one with the HIGHEST permission, then the
    /// unique index <c>UX_AccessGrants_Principal_Scope</c> (in SQL — it spans owner and owned columns, which EF cannot
    /// model).</item>
    /// <item>One live pseudonym per audit subject: older duplicates keep their id (audit entries reference it, the hash
    /// chain covers it) and are set aside as <c>&lt;reference&gt;#&lt;id&gt;</c>, which erasure still finds; then the
    /// filtered unique index.</item>
    /// </list>
    /// The backfills switch the tenant-isolation security policy off and on again (the pattern of
    /// <c>EnvironmentSortOrderBackfill</c>), so they need the privileged migrator connection like those migrations.
    /// </summary>
    public partial class Review3DataIntegrity : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_AuditSubjects_SubjectReference",
                schema: "amkeyward",
                table: "AuditSubjects");

            migrationBuilder.AddColumn<int>(
                name: "LastVersionNumber",
                schema: "amkeyward",
                table: "VaultItems",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<string>(
                name: "NameBeforeAgentRename",
                schema: "amkeyward",
                table: "VaultItems",
                type: "nvarchar(256)",
                maxLength: 256,
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "RenamedByAgentTokenId",
                schema: "amkeyward",
                table: "VaultItems",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "Revision",
                schema: "amkeyward",
                table: "VaultItems",
                type: "uniqueidentifier",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "DeletedAt",
                schema: "amkeyward",
                table: "Users",
                type: "datetimeoffset",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ItemNameAtRequest",
                schema: "amkeyward",
                table: "RevealRequests",
                type: "nvarchar(256)",
                maxLength: 256,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "ItemNameBeforeAgentRename",
                schema: "amkeyward",
                table: "RevealRequests",
                type: "nvarchar(256)",
                maxLength: 256,
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "ItemRevisionAtRequest",
                schema: "amkeyward",
                table: "RevealRequests",
                type: "uniqueidentifier",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "LastUsedAt",
                schema: "amkeyward",
                table: "AgentTokens",
                type: "datetimeoffset",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "LastUsedIp",
                schema: "amkeyward",
                table: "AgentTokens",
                type: "nvarchar(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.Sql(PolicyOff);

            migrationBuilder.Sql("""
                UPDATE i SET
                    [Revision] = ISNULL(i.[CurrentVersionId], NEWID()),
                    [LastVersionNumber] = ISNULL((SELECT MAX(v.[VersionNumber]) FROM [amkeyward].[VaultItemVersions] v WHERE v.[VaultItemId] = i.[Id]), 0)
                FROM [amkeyward].[VaultItems] i;

                UPDATE r SET
                    [ItemNameAtRequest] = i.[Name],
                    [ItemRevisionAtRequest] = i.[Revision]
                FROM [amkeyward].[RevealRequests] r
                JOIN [amkeyward].[VaultItems] i ON i.[Id] = r.[ItemId];

                WITH RankedGrants AS (
                    SELECT ROW_NUMBER() OVER (
                               PARTITION BY [PrincipalType], [PrincipalId], [ScopeKind], [ScopeTargetId]
                               ORDER BY CASE [Permission] WHEN 'Manage' THEN 0 WHEN 'Write' THEN 1 ELSE 2 END, [CreatedAt], [Id]) AS [Rank]
                    FROM [amkeyward].[AccessGrants]
                )
                DELETE FROM RankedGrants WHERE [Rank] > 1;

                WITH RankedSubjects AS (
                    SELECT [SubjectReference], [Id],
                           ROW_NUMBER() OVER (PARTITION BY [SubjectReference] ORDER BY [CreatedAt], [Id]) AS [Rank]
                    FROM [amkeyward].[AuditSubjects]
                    WHERE [ErasedAt] IS NULL
                )
                UPDATE RankedSubjects
                SET [SubjectReference] = LEFT([SubjectReference], 219) + N'#' + CONVERT(nvarchar(36), [Id])
                WHERE [Rank] > 1;
                """);

            migrationBuilder.Sql(PolicyOn);

            migrationBuilder.Sql(
                "CREATE UNIQUE INDEX [UX_AccessGrants_Principal_Scope] ON [amkeyward].[AccessGrants] ([PrincipalType], [PrincipalId], [ScopeKind], [ScopeTargetId]);");

            migrationBuilder.CreateIndex(
                name: "IX_AuditSubjects_SubjectReference",
                schema: "amkeyward",
                table: "AuditSubjects",
                column: "SubjectReference",
                unique: true,
                filter: "[ErasedAt] IS NULL");
        }

        private const string PolicyOff = """
            IF EXISTS (SELECT 1 FROM sys.security_policies sp JOIN sys.schemas s ON s.schema_id = sp.schema_id
                       WHERE sp.name = 'TenantIsolationPolicy' AND s.name = 'amkeyward')
                ALTER SECURITY POLICY amkeyward.TenantIsolationPolicy WITH (STATE = OFF);
            """;

        private const string PolicyOn = """
            IF EXISTS (SELECT 1 FROM sys.security_policies sp JOIN sys.schemas s ON s.schema_id = sp.schema_id
                       WHERE sp.name = 'TenantIsolationPolicy' AND s.name = 'amkeyward')
                ALTER SECURITY POLICY amkeyward.TenantIsolationPolicy WITH (STATE = ON);
            """;

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // The removed duplicate grants and the set-aside pseudonym references are not restored.
            migrationBuilder.Sql("DROP INDEX IF EXISTS [UX_AccessGrants_Principal_Scope] ON [amkeyward].[AccessGrants];");

            migrationBuilder.DropIndex(
                name: "IX_AuditSubjects_SubjectReference",
                schema: "amkeyward",
                table: "AuditSubjects");

            migrationBuilder.DropColumn(
                name: "LastVersionNumber",
                schema: "amkeyward",
                table: "VaultItems");

            migrationBuilder.DropColumn(
                name: "NameBeforeAgentRename",
                schema: "amkeyward",
                table: "VaultItems");

            migrationBuilder.DropColumn(
                name: "RenamedByAgentTokenId",
                schema: "amkeyward",
                table: "VaultItems");

            migrationBuilder.DropColumn(
                name: "Revision",
                schema: "amkeyward",
                table: "VaultItems");

            migrationBuilder.DropColumn(
                name: "DeletedAt",
                schema: "amkeyward",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "ItemNameAtRequest",
                schema: "amkeyward",
                table: "RevealRequests");

            migrationBuilder.DropColumn(
                name: "ItemNameBeforeAgentRename",
                schema: "amkeyward",
                table: "RevealRequests");

            migrationBuilder.DropColumn(
                name: "ItemRevisionAtRequest",
                schema: "amkeyward",
                table: "RevealRequests");

            migrationBuilder.DropColumn(
                name: "LastUsedAt",
                schema: "amkeyward",
                table: "AgentTokens");

            migrationBuilder.DropColumn(
                name: "LastUsedIp",
                schema: "amkeyward",
                table: "AgentTokens");

            migrationBuilder.CreateIndex(
                name: "IX_AuditSubjects_SubjectReference",
                schema: "amkeyward",
                table: "AuditSubjects",
                column: "SubjectReference");
        }
    }
}
