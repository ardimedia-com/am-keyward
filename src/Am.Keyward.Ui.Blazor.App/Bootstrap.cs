using System.Security.Cryptography;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Identity;
using Am.Keyward.Core.Domain.Software;
using Am.Keyward.Infrastructure.Persistence;
using EnvironmentName = Am.Keyward.Core.Domain.ValueObjects.EnvironmentName;
using Microsoft.EntityFrameworkCore;

namespace Am.Keyward.Ui.Blazor.App;

/// <summary>
/// Dev-only KEK bootstrap: loads or creates a local 32-byte key file outside the database. A real
/// deployment configures a proper KEK provider (Azure Key Vault / HSM) instead — see SECURITY.md.
/// </summary>
public static class DevKek
{
    public static (byte[] Key, string KekId) LoadOrCreate(string contentRoot)
    {
        var path = Path.Combine(contentRoot, "kek.dev.key");
        if (File.Exists(path))
        {
            return (Convert.FromBase64String(File.ReadAllText(path).Trim()), "dev-file:v1");
        }

        var key = RandomNumberGenerator.GetBytes(32);
        File.WriteAllText(path, Convert.ToBase64String(key));
        return (key, "dev-file:v1");
    }
}

/// <summary>A fixed demo tenant + project (Development/Test/Preview/Production) so the reference UI has a target.</summary>
public static class Demo
{
    public static readonly Guid TenantId = Guid.Parse("11111111-1111-1111-1111-111111111111");
    public static readonly Guid ProjectId = Guid.Parse("22222222-2222-2222-2222-222222222222");

    public static async Task EnsureSeededAsync(KeywardDbContext db)
    {
        if (await db.Tenants.AnyAsync(t => t.Id == TenantId))
        {
            return;
        }

        var now = DateTimeOffset.UtcNow;
        db.Tenants.Add(new Tenant(TenantId, "Demo (system)", isSystemTenant: true, now));

        var project = new Project(ProjectId, TenantId, OwnerType.Tenant, TenantId, "demo", now);
        foreach (var environment in EnvironmentName.DefaultSet)
        {
            project.AddEnvironment(Guid.NewGuid(), environment, now);
        }

        db.Projects.Add(project);
        await db.SaveChangesAsync();
    }
}
