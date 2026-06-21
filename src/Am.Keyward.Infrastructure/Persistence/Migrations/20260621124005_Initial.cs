using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Am.Keyward.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class Initial : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.EnsureSchema(
                name: "amkeyward");

            migrationBuilder.CreateTable(
                name: "AuditEntries",
                schema: "amkeyward",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    Sequence = table.Column<long>(type: "bigint", nullable: false),
                    Action = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    ResourceType = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                    ResourceId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    ActorPseudonymId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    OccurredAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    PreviousHash = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    Hash = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuditEntries", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Projects",
                schema: "amkeyward",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    OwnerType = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: false),
                    OwnerId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Projects", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "SoftwareSecrets",
                schema: "amkeyward",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ProjectId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Key = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: false),
                    CreatedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SoftwareSecrets", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Tenants",
                schema: "amkeyward",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    IsSystemTenant = table.Column<bool>(type: "bit", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Tenants", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Users",
                schema: "amkeyward",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Issuer = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: true),
                    ExternalId = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: false),
                    DisplayName = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    IsSystemAdmin = table.Column<bool>(type: "bit", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Users", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "RuntimeEnvironments",
                schema: "amkeyward",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ProjectId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RuntimeEnvironments", x => x.Id);
                    table.ForeignKey(
                        name: "FK_RuntimeEnvironments_Projects_ProjectId",
                        column: x => x.ProjectId,
                        principalSchema: "amkeyward",
                        principalTable: "Projects",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "SecretValues",
                schema: "amkeyward",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    SoftwareSecretId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    EnvironmentId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CurrentVersionId = table.Column<Guid>(type: "uniqueidentifier", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SecretValues", x => x.Id);
                    table.ForeignKey(
                        name: "FK_SecretValues_SoftwareSecrets_SoftwareSecretId",
                        column: x => x.SoftwareSecretId,
                        principalSchema: "amkeyward",
                        principalTable: "SoftwareSecrets",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "SecretVersions",
                schema: "amkeyward",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    SecretValueId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    VersionNumber = table.Column<int>(type: "int", nullable: false),
                    Encrypted = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SecretVersions", x => x.Id);
                    table.ForeignKey(
                        name: "FK_SecretVersions_SecretValues_SecretValueId",
                        column: x => x.SecretValueId,
                        principalSchema: "amkeyward",
                        principalTable: "SecretValues",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AuditEntries_TenantId_Sequence",
                schema: "amkeyward",
                table: "AuditEntries",
                columns: new[] { "TenantId", "Sequence" },
                unique: true,
                filter: "[TenantId] IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_RuntimeEnvironments_ProjectId_Name",
                schema: "amkeyward",
                table: "RuntimeEnvironments",
                columns: new[] { "ProjectId", "Name" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_SecretValues_SoftwareSecretId_EnvironmentId",
                schema: "amkeyward",
                table: "SecretValues",
                columns: new[] { "SoftwareSecretId", "EnvironmentId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_SecretVersions_SecretValueId_VersionNumber",
                schema: "amkeyward",
                table: "SecretVersions",
                columns: new[] { "SecretValueId", "VersionNumber" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_SoftwareSecrets_ProjectId_Key",
                schema: "amkeyward",
                table: "SoftwareSecrets",
                columns: new[] { "ProjectId", "Key" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Users_Issuer_ExternalId",
                schema: "amkeyward",
                table: "Users",
                columns: new[] { "Issuer", "ExternalId" },
                unique: true,
                filter: "[Issuer] IS NOT NULL");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AuditEntries",
                schema: "amkeyward");

            migrationBuilder.DropTable(
                name: "RuntimeEnvironments",
                schema: "amkeyward");

            migrationBuilder.DropTable(
                name: "SecretVersions",
                schema: "amkeyward");

            migrationBuilder.DropTable(
                name: "Tenants",
                schema: "amkeyward");

            migrationBuilder.DropTable(
                name: "Users",
                schema: "amkeyward");

            migrationBuilder.DropTable(
                name: "Projects",
                schema: "amkeyward");

            migrationBuilder.DropTable(
                name: "SecretValues",
                schema: "amkeyward");

            migrationBuilder.DropTable(
                name: "SoftwareSecrets",
                schema: "amkeyward");
        }
    }
}
