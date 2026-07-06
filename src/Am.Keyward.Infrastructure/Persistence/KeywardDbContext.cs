using System.Text.Json;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Domain.Access;
using Am.Keyward.Core.Domain.Audit;
using Am.Keyward.Core.Domain.Human;
using Am.Keyward.Core.Domain.Identity;
using Am.Keyward.Core.Domain.Software;
using Am.Keyward.Core.Domain.ValueObjects;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace Am.Keyward.Infrastructure.Persistence;

/// <summary>
/// The AM KEYWARD database context. All tables live in the dedicated <see cref="Schema"/> so the
/// library can be embedded in a host's existing database without colliding; the migrations-history
/// table is scoped to the same schema (configured by callers, see the design-time factory and DI).
/// Tenant isolation is enforced by a global query filter keyed on the ambient <see cref="ICurrentTenant"/>
/// (read per query), backed in depth by SQL Server row-level security (see the SESSION_CONTEXT
/// interceptor and the TenancyIsolation migration).
/// </summary>
public sealed class KeywardDbContext(DbContextOptions<KeywardDbContext> options, ICurrentTenant tenant, ICurrentUser user)
    : DbContext(options)
{
    public const string Schema = "amkeyward";

    private readonly ICurrentTenant _tenant = tenant;
    private readonly ICurrentUser _user = user;

    public DbSet<Tenant> Tenants => Set<Tenant>();
    public DbSet<AppUser> Users => Set<AppUser>();
    public DbSet<TenantMembership> TenantMemberships => Set<TenantMembership>();
    public DbSet<Project> Projects => Set<Project>();
    public DbSet<RuntimeEnvironment> RuntimeEnvironments => Set<RuntimeEnvironment>();
    public DbSet<SoftwareSecret> SoftwareSecrets => Set<SoftwareSecret>();
    public DbSet<SecretValue> SecretValues => Set<SecretValue>();
    public DbSet<SecretVersion> SecretVersions => Set<SecretVersion>();
    public DbSet<SoftwareClientToken> SoftwareClientTokens => Set<SoftwareClientToken>();
    public DbSet<Vault> Vaults => Set<Vault>();
    public DbSet<Folder> Folders => Set<Folder>();
    public DbSet<VaultItem> VaultItems => Set<VaultItem>();
    public DbSet<VaultItemVersion> VaultItemVersions => Set<VaultItemVersion>();
    public DbSet<AccessGrant> AccessGrants => Set<AccessGrant>();
    public DbSet<BreakGlassGrant> BreakGlassGrants => Set<BreakGlassGrant>();
    public DbSet<AuditEntry> AuditEntries => Set<AuditEntry>();
    public DbSet<AuditSubject> AuditSubjects => Set<AuditSubject>();

    protected override void OnModelCreating(ModelBuilder model)
    {
        model.HasDefaultSchema(Schema);

        var json = new JsonSerializerOptions(JsonSerializerDefaults.Web);

        var encryptedConverter = new ValueConverter<EncryptedValue, string>(
            v => JsonSerializer.Serialize(v, json),
            s => JsonSerializer.Deserialize<EncryptedValue>(s, json)!);

        var secretKeyConverter = new ValueConverter<SecretKey, string>(
            k => k.Value,
            s => SecretKey.Create(s));

        var envNameConverter = new ValueConverter<EnvironmentName, string>(
            n => n.Value,
            s => EnvironmentName.Create(s));

        model.Entity<Tenant>(e =>
        {
            e.ToTable("Tenants");
            e.HasKey(x => x.Id);
            e.Property(x => x.Name).HasMaxLength(256).IsRequired();
            e.HasQueryFilter(x => x.Id == _tenant.TenantId);
        });

        model.Entity<AppUser>(e =>
        {
            e.ToTable("Users");
            e.HasKey(x => x.Id);
            e.Property(x => x.Issuer).HasMaxLength(512);
            e.Property(x => x.ExternalId).HasMaxLength(512).IsRequired();
            e.Property(x => x.DisplayName).HasMaxLength(256).IsRequired();
            // External users are unique per (Issuer, ExternalId). Local users have a null Issuer, which the
            // composite index does not constrain (SQL Server treats each null as distinct in a multi-column
            // unique index), so add a filtered unique index on ExternalId for local users — otherwise two
            // concurrent just-in-time creations for the same local Identity user could insert duplicate rows.
            e.HasIndex(x => new { x.Issuer, x.ExternalId }).IsUnique();
            e.HasIndex(x => x.ExternalId).IsUnique().HasFilter("[Issuer] IS NULL");
        });

        // Tenant membership: which installation-global users belong to which tenant, with a per-tenant role.
        // Installation-global (looked up at the host edge before/independent of the tenant scope, to gate a
        // caller-supplied {tenantId}), so — like the token and audit-subject tables — it has deliberately NO
        // tenant query filter and is NOT in the row-level-security policy.
        model.Entity<TenantMembership>(e =>
        {
            e.ToTable("TenantMemberships");
            e.HasKey(x => x.Id);
            e.Property(x => x.Role).HasConversion<string>().HasMaxLength(16);
            e.HasIndex(x => new { x.TenantId, x.UserId }).IsUnique();
            e.HasIndex(x => x.UserId);
        });

        model.Entity<Project>(e =>
        {
            e.ToTable("Projects");
            e.HasKey(x => x.Id);
            e.Property(x => x.Name).HasMaxLength(256).IsRequired();
            e.Property(x => x.OwnerType).HasConversion<string>().HasMaxLength(16);
            e.HasIndex(x => x.TenantId);
            e.HasMany(x => x.Environments).WithOne().HasForeignKey(x => x.ProjectId).OnDelete(DeleteBehavior.Cascade);
            e.Navigation(x => x.Environments).UsePropertyAccessMode(PropertyAccessMode.Field);
            e.HasQueryFilter(x => x.TenantId == _tenant.TenantId);
        });

        model.Entity<RuntimeEnvironment>(e =>
        {
            e.ToTable("RuntimeEnvironments");
            e.HasKey(x => x.Id);
            e.Property(x => x.Name).HasConversion(envNameConverter).HasMaxLength(128).IsRequired();
            e.HasIndex(x => new { x.ProjectId, x.Name }).IsUnique();
            e.HasIndex(x => x.TenantId);
            e.HasQueryFilter(x => x.TenantId == _tenant.TenantId);
        });

        model.Entity<SoftwareSecret>(e =>
        {
            e.ToTable("SoftwareSecrets");
            e.HasKey(x => x.Id);
            e.Property(x => x.Key).HasConversion(secretKeyConverter).HasMaxLength(512).IsRequired();
            e.HasIndex(x => new { x.ProjectId, x.Key }).IsUnique(); // one key per project
            e.HasIndex(x => x.TenantId);
            e.HasMany(x => x.Values).WithOne().HasForeignKey(x => x.SoftwareSecretId).OnDelete(DeleteBehavior.Cascade);
            e.Navigation(x => x.Values).UsePropertyAccessMode(PropertyAccessMode.Field);
            e.HasQueryFilter(x => x.TenantId == _tenant.TenantId);
        });

        model.Entity<SecretValue>(e =>
        {
            e.ToTable("SecretValues");
            e.HasKey(x => x.Id);
            e.HasIndex(x => new { x.SoftwareSecretId, x.EnvironmentId }).IsUnique(); // one value per (secret, environment)
            e.HasIndex(x => x.TenantId);
            e.HasMany(x => x.Versions).WithOne().HasForeignKey(x => x.SecretValueId).OnDelete(DeleteBehavior.Cascade);
            e.Navigation(x => x.Versions).UsePropertyAccessMode(PropertyAccessMode.Field);
            e.HasQueryFilter(x => x.TenantId == _tenant.TenantId);
        });

        model.Entity<SecretVersion>(e =>
        {
            e.ToTable("SecretVersions");
            e.HasKey(x => x.Id);
            e.Property(x => x.Encrypted).HasConversion(encryptedConverter).IsRequired();
            e.HasIndex(x => new { x.SecretValueId, x.VersionNumber }).IsUnique();
            e.HasIndex(x => x.TenantId);
            e.HasQueryFilter(x => x.TenantId == _tenant.TenantId);
        });

        model.Entity<SoftwareClientToken>(e =>
        {
            e.ToTable("SoftwareClientTokens");
            e.HasKey(x => x.Id);
            e.Property(x => x.Name).HasMaxLength(256).IsRequired();
            e.Property(x => x.Note).HasMaxLength(1024).IsRequired();
            e.Property(x => x.TokenPrefix).HasMaxLength(64).IsRequired();
            e.Property(x => x.TokenHash).HasMaxLength(128).IsRequired();
            e.HasIndex(x => x.TokenPrefix).IsUnique();
            e.HasIndex(x => new { x.TenantId, x.ProjectId });
            // Installation-global authentication table: deliberately NO tenant query filter and NOT in the
            // row-level-security policy — it must be looked up by prefix BEFORE the tenant is known. The
            // record carries TenantId only to scope the request once the token is authenticated. It holds
            // no secret material (only a hash + a non-secret prefix).
        });

        // Human vaults. Isolation boundary: tenant vaults by TenantId, personal (tenant-less) vaults by
        // OwnerUserId. (Finer per-user/group sharing via AccessGrant is layered on in the application.)
        model.Entity<Vault>(e =>
        {
            e.ToTable("Vaults");
            e.HasKey(x => x.Id);
            e.Property(x => x.Name).HasMaxLength(256).IsRequired();
            e.Property(x => x.OwnerType).HasConversion<string>().HasMaxLength(16);
            e.Property(x => x.ProtectionMode).HasConversion<string>().HasMaxLength(16);
            e.HasIndex(x => x.TenantId);
            e.HasIndex(x => x.OwnerUserId);
            e.HasMany(x => x.Folders).WithOne().HasForeignKey(x => x.VaultId).OnDelete(DeleteBehavior.Cascade);
            e.Navigation(x => x.Folders).UsePropertyAccessMode(PropertyAccessMode.Field);
            e.HasQueryFilter(x =>
                (x.TenantId != null && x.TenantId == _tenant.TenantId)
                || (x.TenantId == null && x.OwnerUserId == _user.UserId));
        });

        model.Entity<Folder>(e =>
        {
            e.ToTable("Folders");
            e.HasKey(x => x.Id);
            e.Property(x => x.Name).HasMaxLength(256).IsRequired();
            e.HasIndex(x => x.VaultId);
            e.HasIndex(x => x.TenantId);
            e.HasIndex(x => x.OwnerUserId);
            e.HasQueryFilter(x =>
                (x.TenantId != null && x.TenantId == _tenant.TenantId)
                || (x.TenantId == null && x.OwnerUserId == _user.UserId));
        });

        model.Entity<VaultItem>(e =>
        {
            e.ToTable("VaultItems");
            e.HasKey(x => x.Id);
            e.Property(x => x.Type).HasConversion<string>().HasMaxLength(32);
            e.Property(x => x.Name).HasMaxLength(256).IsRequired();
            e.HasIndex(x => x.VaultId);
            e.HasIndex(x => x.FolderId);
            e.HasIndex(x => x.TenantId);
            e.HasIndex(x => x.OwnerUserId);
            e.HasMany(x => x.Versions).WithOne().HasForeignKey(x => x.VaultItemId).OnDelete(DeleteBehavior.Cascade);
            e.Navigation(x => x.Versions).UsePropertyAccessMode(PropertyAccessMode.Field);
            e.HasQueryFilter(x =>
                (x.TenantId != null && x.TenantId == _tenant.TenantId)
                || (x.TenantId == null && x.OwnerUserId == _user.UserId));
        });

        model.Entity<VaultItemVersion>(e =>
        {
            e.ToTable("VaultItemVersions");
            e.HasKey(x => x.Id);
            e.Property(x => x.Encrypted).HasConversion(encryptedConverter).IsRequired();
            e.HasIndex(x => new { x.VaultItemId, x.VersionNumber }).IsUnique();
            e.HasIndex(x => x.TenantId);
            e.HasIndex(x => x.OwnerUserId);
            e.HasQueryFilter(x =>
                (x.TenantId != null && x.TenantId == _tenant.TenantId)
                || (x.TenantId == null && x.OwnerUserId == _user.UserId));
        });

        // Access grants share a tenant-owned resource (here: a vault) with a user or group. Tenant-scoped
        // (cross-tenant grants are forbidden in v0.1). The grant is the authorization layer on top of the
        // tenant isolation boundary; access decisions go through IKeywardAccessPolicy.
        model.Entity<AccessGrant>(e =>
        {
            e.ToTable("AccessGrants");
            e.HasKey(x => x.Id);
            e.Property(x => x.PrincipalType).HasConversion<string>().HasMaxLength(16);
            e.Property(x => x.Permission).HasConversion<string>().HasMaxLength(16);
            e.OwnsOne(x => x.Scope, s =>
            {
                s.Property(p => p.Kind).HasConversion<string>().HasMaxLength(16).HasColumnName("ScopeKind");
                s.Property(p => p.TargetId).HasColumnName("ScopeTargetId");
            });
            e.HasIndex(x => x.TenantId);
            e.HasIndex(x => new { x.PrincipalType, x.PrincipalId });
            e.HasQueryFilter(x => x.TenantId == _tenant.TenantId);
        });

        // Break-glass grants: dual-control emergency access. Installation-global (a cross-tenant System-Admin
        // capability gated by an explicit system-admin check), so deliberately NO tenant query filter and
        // NOT in row-level security — the grant carries the target's TenantId only to scope the recovery.
        model.Entity<BreakGlassGrant>(e =>
        {
            e.ToTable("BreakGlassGrants");
            e.HasKey(x => x.Id);
            e.Property(x => x.Reason).HasMaxLength(1024).IsRequired();
            e.Property(x => x.Status).HasConversion<string>().HasMaxLength(16);
            e.OwnsOne(x => x.Scope, s =>
            {
                s.Property(p => p.Kind).HasConversion<string>().HasMaxLength(16).HasColumnName("ScopeKind");
                s.Property(p => p.TargetId).HasColumnName("ScopeTargetId");
            });
            // Optimistic concurrency: serialize the approve/reject/consume transitions so a single-use grant
            // cannot be consumed twice by two racing callers (the second SaveChanges fails).
            e.Property(x => x.RowVersion).IsRowVersion();
            e.HasIndex(x => x.Status);
            e.HasIndex(x => x.TenantId);
        });

        model.Entity<AuditEntry>(e =>
        {
            e.ToTable("AuditEntries");
            e.HasKey(x => x.Id);
            e.Property(x => x.Action).HasConversion<string>().HasMaxLength(32);
            e.Property(x => x.ResourceType).HasMaxLength(128).IsRequired();
            e.Property(x => x.PreviousHash).HasMaxLength(64).IsRequired();
            e.Property(x => x.Hash).HasMaxLength(64).IsRequired();
            e.HasIndex(x => new { x.TenantId, x.Sequence }).IsUnique();
            e.HasQueryFilter(x => x.TenantId == _tenant.TenantId);
        });

        // Crypto-shredding directory: maps an audit pseudonym to the actor's PII, encrypted under a
        // per-subject DEK. Installation-global (a subject is stable across tenants), so — like the token
        // table — it has deliberately NO tenant query filter and is NOT in the row-level-security policy:
        // it is looked up by pseudonym/subject reference independent of the active tenant, and holds only
        // ciphertext (cleared on erasure), never plaintext PII.
        model.Entity<AuditSubject>(e =>
        {
            e.ToTable("AuditSubjects");
            e.HasKey(x => x.Id);
            e.Property(x => x.SubjectReference).HasMaxLength(256).IsRequired();
            // Nullable converter (NULL once erased) — a dedicated converter keeps the column nullable.
            e.Property(x => x.EncryptedPii).HasConversion(
                v => v == null ? null : JsonSerializer.Serialize(v, json),
                s => s == null ? null : JsonSerializer.Deserialize<EncryptedValue>(s, json));
            e.HasIndex(x => x.SubjectReference);
        });
    }
}
