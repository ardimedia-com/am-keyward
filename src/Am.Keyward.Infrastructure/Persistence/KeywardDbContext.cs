using System.Text.Json;
using Am.Keyward.Core.Domain.Audit;
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
/// </summary>
public sealed class KeywardDbContext(DbContextOptions<KeywardDbContext> options) : DbContext(options)
{
    public const string Schema = "amkeyward";

    public DbSet<Tenant> Tenants => Set<Tenant>();
    public DbSet<AppUser> Users => Set<AppUser>();
    public DbSet<Project> Projects => Set<Project>();
    public DbSet<RuntimeEnvironment> RuntimeEnvironments => Set<RuntimeEnvironment>();
    public DbSet<SoftwareSecret> SoftwareSecrets => Set<SoftwareSecret>();
    public DbSet<SecretValue> SecretValues => Set<SecretValue>();
    public DbSet<SecretVersion> SecretVersions => Set<SecretVersion>();
    public DbSet<AuditEntry> AuditEntries => Set<AuditEntry>();

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
        });

        model.Entity<AppUser>(e =>
        {
            e.ToTable("Users");
            e.HasKey(x => x.Id);
            e.Property(x => x.Issuer).HasMaxLength(512);
            e.Property(x => x.ExternalId).HasMaxLength(512).IsRequired();
            e.Property(x => x.DisplayName).HasMaxLength(256).IsRequired();
            e.HasIndex(x => new { x.Issuer, x.ExternalId }).IsUnique();
        });

        model.Entity<Project>(e =>
        {
            e.ToTable("Projects");
            e.HasKey(x => x.Id);
            e.Property(x => x.Name).HasMaxLength(256).IsRequired();
            e.Property(x => x.OwnerType).HasConversion<string>().HasMaxLength(16);
            e.HasMany(x => x.Environments).WithOne().HasForeignKey(x => x.ProjectId).OnDelete(DeleteBehavior.Cascade);
            e.Navigation(x => x.Environments).UsePropertyAccessMode(PropertyAccessMode.Field);
        });

        model.Entity<RuntimeEnvironment>(e =>
        {
            e.ToTable("RuntimeEnvironments");
            e.HasKey(x => x.Id);
            e.Property(x => x.Name).HasConversion(envNameConverter).HasMaxLength(128).IsRequired();
            e.HasIndex(x => new { x.ProjectId, x.Name }).IsUnique();
        });

        model.Entity<SoftwareSecret>(e =>
        {
            e.ToTable("SoftwareSecrets");
            e.HasKey(x => x.Id);
            e.Property(x => x.Key).HasConversion(secretKeyConverter).HasMaxLength(512).IsRequired();
            e.HasIndex(x => new { x.ProjectId, x.Key }).IsUnique(); // one key per project
            e.HasMany(x => x.Values).WithOne().HasForeignKey(x => x.SoftwareSecretId).OnDelete(DeleteBehavior.Cascade);
            e.Navigation(x => x.Values).UsePropertyAccessMode(PropertyAccessMode.Field);
        });

        model.Entity<SecretValue>(e =>
        {
            e.ToTable("SecretValues");
            e.HasKey(x => x.Id);
            e.HasIndex(x => new { x.SoftwareSecretId, x.EnvironmentId }).IsUnique(); // one value per (secret, environment)
            e.HasMany(x => x.Versions).WithOne().HasForeignKey(x => x.SecretValueId).OnDelete(DeleteBehavior.Cascade);
            e.Navigation(x => x.Versions).UsePropertyAccessMode(PropertyAccessMode.Field);
        });

        model.Entity<SecretVersion>(e =>
        {
            e.ToTable("SecretVersions");
            e.HasKey(x => x.Id);
            e.Property(x => x.Encrypted).HasConversion(encryptedConverter).IsRequired();
            e.HasIndex(x => new { x.SecretValueId, x.VersionNumber }).IsUnique();
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
        });
    }
}
