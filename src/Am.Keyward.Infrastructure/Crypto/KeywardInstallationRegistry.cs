using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Domain.KeyCustody;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Am.Keyward.Infrastructure.Crypto;

/// <summary>
/// Records this installation in the database on every start and reports the others it finds there.
///
/// <para>Purely diagnostic: the canary decides whether the key owns the data, this says who is involved.
/// Nothing depends on the rows being complete, so every operation here is best-effort by design.</para>
/// </summary>
public sealed class KeywardInstallationRegistry(
    IDbContextFactory<KeywardDbContext> dbFactory,
    IKekProvider kek,
    IClock clock,
    IOptions<KeywardKeyIntegrityOptions> options)
{
    /// <summary>Identity of the currently running installation.</summary>
    public (string MachineName, string EnvironmentName, string ApplicationName) Current { get; } =
        (Environment.MachineName,
         Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT")
            ?? Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT")
            ?? "unknown",
         System.Reflection.Assembly.GetEntryAssembly()?.GetName().Name ?? "unknown");

    /// <summary>
    /// Upserts this installation's row and returns every OTHER installation seen recently enough to still be
    /// running (see <see cref="KeywardKeyIntegrityOptions.PeerStaleAfterDays"/>) — a decommissioned
    /// deployment should not keep raising questions forever.
    /// </summary>
    public async Task<IReadOnlyList<KeywardInstallation>> RecordAndListPeersAsync(CancellationToken ct = default)
    {
        await using KeywardDbContext db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);

        string key = KeywardInstallation.KeyFor(Current.MachineName, Current.EnvironmentName, Current.ApplicationName);
        DateTimeOffset now = clock.UtcNow;
        string? schemaVersion = (await db.Database.GetAppliedMigrationsAsync(ct).ConfigureAwait(false)).LastOrDefault();

        KeywardInstallation? mine = await db.Installations
            .FirstOrDefaultAsync(i => i.InstallationKey == key, ct).ConfigureAwait(false);

        if (mine is null)
        {
            db.Installations.Add(new KeywardInstallation(
                Guid.NewGuid(), key, Current.MachineName, Current.EnvironmentName, Current.ApplicationName,
                kek.KekId, options.Value.KeyCustodyLocation, schemaVersion, now, now));
        }
        else
        {
            mine.Seen(kek.KekId, options.Value.KeyCustodyLocation, schemaVersion, now);
        }

        try
        {
            await db.SaveChangesAsync(ct).ConfigureAwait(false);
        }
        catch (DbUpdateException)
        {
            // Two starts of the same installation raced on the unique key. The row exists either way, which
            // is all this is for.
            db.ChangeTracker.Clear();
        }

        DateTimeOffset freshSince = now.AddDays(-options.Value.PeerStaleAfterDays);
        return await db.Installations.AsNoTracking()
            .Where(i => i.InstallationKey != key && i.LastSeenAt >= freshSince)
            .OrderBy(i => i.EnvironmentName).ThenBy(i => i.MachineName)
            .ToListAsync(ct).ConfigureAwait(false);
    }

    /// <summary>Every installation on this database, recent first — for a host's status page.</summary>
    public async Task<IReadOnlyList<KeywardInstallation>> ListAsync(CancellationToken ct = default)
    {
        await using KeywardDbContext db = await dbFactory.CreateDbContextAsync(ct).ConfigureAwait(false);
        return await db.Installations.AsNoTracking()
            .OrderByDescending(i => i.LastSeenAt)
            .ToListAsync(ct).ConfigureAwait(false);
    }
}
