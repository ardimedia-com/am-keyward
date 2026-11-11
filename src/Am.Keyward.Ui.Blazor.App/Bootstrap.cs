using System.Security.Cryptography;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Identity;
using Am.Keyward.Core.Domain.Software;
using Am.Keyward.Infrastructure.Crypto;
using Am.Keyward.Infrastructure.Persistence;
using EnvironmentName = Am.Keyward.Core.Domain.ValueObjects.EnvironmentName;
using Microsoft.EntityFrameworkCore;

namespace Am.Keyward.Ui.Blazor.App;

/// <summary>
/// Development-only KEK bootstrap: loads or creates a local 32-byte key file (plain Base64, gitignored) in the
/// content root. NEVER used outside Development — a deploy that replaces the site folder would replace the key and
/// make every stored secret unreadable; <see cref="ShellKek"/> picks the DPAPI key file there instead.
/// </summary>
public static class DevKek
{
    /// <summary>File name of the development key in the content root.</summary>
    public const string FileName = "kek.dev.key";

    /// <summary>Format id of the development key; returned qualified with the key's fingerprint.</summary>
    public const string FormatId = "dev-file:v1";

    public static (byte[] Key, string KekId) LoadOrCreate(string contentRoot)
    {
        var path = Path.Combine(contentRoot, FileName);
        if (File.Exists(path))
        {
            var existing = Convert.FromBase64String(File.ReadAllText(path).Trim());
            return (existing, KekFingerprint.Qualify(FormatId, existing));
        }

        var key = RandomNumberGenerator.GetBytes(32);
        File.WriteAllText(path, Convert.ToBase64String(key));
        return (key, KekFingerprint.Qualify(FormatId, key));
    }
}

/// <summary>The KEK the shell starts with, where it lives, and whether it was created on this start.</summary>
public sealed record ShellKekResult(byte[] Key, string KekId, string Location, bool Created);

/// <summary>
/// Chooses the key-encryption key of the reference shell. Development: the plaintext <see cref="DevKek"/> file
/// in the content root (unless <c>Keyward:Kek:Directory</c> is set). Every other environment: the DPAPI-protected
/// <see cref="DpapiKekFile"/> in <c>Keyward:Kek:Directory</c> (default
/// <c>%ProgramData%\Ardimedia\Am.Keyward\kek</c>, outside any deploy folder) — Windows only; elsewhere the shell
/// refuses to start, because it has no other key custody to offer.
/// </summary>
public static class ShellKek
{
    /// <summary>Directory of the DPAPI-protected KEK file.</summary>
    public const string DirectoryKey = "Keyward:Kek:Directory";

    /// <summary>The default KEK directory outside Development.</summary>
    public static string DefaultDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Ardimedia", "Am.Keyward", "kek");

    /// <summary>
    /// Loads (or on first run creates) the KEK. Returns the error message instead when the shell must not start.
    /// </summary>
    public static (ShellKekResult? Kek, string? Error) Load(
        IConfiguration configuration, string contentRootPath, bool isDevelopment, ILogger? logger = null)
    {
        var configuredDirectory = configuration[DirectoryKey];
        if (isDevelopment && string.IsNullOrWhiteSpace(configuredDirectory))
        {
            var (devKey, devId) = DevKek.LoadOrCreate(contentRootPath);
            return (new ShellKekResult(devKey, devId, Path.Combine(contentRootPath, DevKek.FileName), Created: false), null);
        }

        if (!OperatingSystem.IsWindows())
        {
            return (null, "No key-encryption key provider for this platform. Outside Development the reference shell "
                + "keeps the KEK in a DPAPI-protected file, which needs Windows. Host Keyward in your own application "
                + "with a KMS/HSM-backed IKekProvider (AddKeyward overload with a provider factory).");
        }

        // A development key next to a production start means this installation's secrets were written with it:
        // silently creating a fresh DPAPI key would make every one of them unreadable.
        if (!isDevelopment && File.Exists(Path.Combine(contentRootPath, DevKek.FileName)))
        {
            return (null, $"A development key file ({DevKek.FileName}) was found in the content root outside Development. "
                + "Secrets written with it cannot be read with a new key. Run this database in Development, or start "
                + "from an empty database and delete the development key file.");
        }

        var directory = string.IsNullOrWhiteSpace(configuredDirectory) ? DefaultDirectory : configuredDirectory;
        var (key, kekId, created) = DpapiKekFile.LoadOrCreate(directory, logger);
        return (new ShellKekResult(key, kekId, DpapiKekFile.PathIn(directory), created), null);
    }
}

/// <summary>
/// The fixed tenant the single-organization shell hosts, plus an optional demo project
/// (Development/Test/Production environments) so the reference UI has a target.
/// </summary>
public static class Demo
{
    /// <summary>Seeds the demo project outside Development when <c>true</c> (Development seeds it unless <c>false</c>).</summary>
    public const string SeedDemoKey = "Keyward:SeedDemo";

    public static readonly Guid TenantId = Guid.Parse("11111111-1111-1111-1111-111111111111");
    public static readonly Guid ProjectId = Guid.Parse("22222222-2222-2222-2222-222222222222");

    /// <summary>
    /// Ensures the shell's tenant (always — the single-tenant host cannot work without it) and, when
    /// <paramref name="seedDemoProject"/>, the demo project. Idempotent.
    /// </summary>
    public static async Task EnsureSeededAsync(KeywardDbContext db, bool seedDemoProject, CancellationToken ct = default)
    {
        var now = DateTimeOffset.UtcNow;

        // Startup runs without a tenant scope; bypass the tenant query filter for the existence checks.
        if (!await db.Tenants.IgnoreQueryFilters().AnyAsync(t => t.Id == TenantId, ct))
        {
            db.Tenants.Add(new Tenant(TenantId, "Demo (system)", isSystemTenant: true, now));
            await db.SaveChangesAsync(ct);
        }

        if (!seedDemoProject || await db.Projects.IgnoreQueryFilters().AnyAsync(p => p.Id == ProjectId, ct))
        {
            return;
        }

        var project = new Project(ProjectId, TenantId, OwnerType.Tenant, TenantId, "demo", now);
        foreach (var environment in EnvironmentName.DefaultSet)
        {
            project.AddEnvironment(Guid.NewGuid(), environment, now);
        }

        db.Projects.Add(project);
        await db.SaveChangesAsync(ct);
    }
}

// Makes the top-level-statement entry point visible to WebApplicationFactory<Program> in the tests, which boot
// the reference shell for real (a startup that throws — e.g. a minimal-API parameter binding error — must fail a
// test, not a deployment).
public partial class Program;
