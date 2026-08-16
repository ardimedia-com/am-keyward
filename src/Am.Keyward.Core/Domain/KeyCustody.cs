namespace Am.Keyward.Core.Domain.KeyCustody;

/// <summary>
/// One row per database: a known plaintext, wrapped under the KEK of whichever installation created it.
/// Every later start unwraps it and compares — a direct proof that the key this process holds is the key
/// this data was sealed with.
///
/// <para>It exists because the alternative signals are all indirect. The stored <c>KekId</c> names the key's
/// FORMAT, so it cannot tell two keys of the same format apart; and a comparison of machine names or key
/// paths tests a recipe rather than the fact — a key file that was silently regenerated at the very same
/// path on the very same machine (a rebuilt server, a wiped ProgramData, a lost file) satisfies every such
/// rule and still cannot read a single stored value.</para>
///
/// <para>The canary catches all of it at startup instead of at the first read: a second installation
/// writing the same database under a different key, a regenerated key, and a database restored without its
/// key store. It is not a secret — it is a fixed, publicly known value; its ciphertext reveals nothing
/// beyond the fact that some key produced it.</para>
/// </summary>
public sealed class KekCanary
{
    /// <summary>The one and only row. A fixed key makes a concurrent second insert fail loudly instead of duplicating.</summary>
    public const int SingletonId = 1;

    public int Id { get; private set; }

    /// <summary>The <see cref="Abstractions.IKekProvider.KekId"/> in force when the canary was written.</summary>
    public string KekId { get; private set; }

    /// <summary>The known plaintext, wrapped by that KEK.</summary>
    public byte[] Wrapped { get; private set; }

    public DateTimeOffset CreatedAt { get; private set; }

    /// <summary>Machine and environment that wrote it — diagnostic only, so an operator can see where the first install ran.</summary>
    public string CreatedBy { get; private set; }

    public KekCanary(int id, string kekId, byte[] wrapped, DateTimeOffset createdAt, string createdBy)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(kekId);
        ArgumentNullException.ThrowIfNull(wrapped);

        Id = id;
        KekId = kekId;
        Wrapped = wrapped;
        CreatedAt = createdAt;
        CreatedBy = createdBy ?? string.Empty;
    }

    public static KekCanary Create(string kekId, byte[] wrapped, DateTimeOffset createdAt, string createdBy) =>
        new(SingletonId, kekId, wrapped, createdAt, createdBy);
}

/// <summary>
/// One row per installation that has started against this database, refreshed on every start.
///
/// <para>The canary answers <i>does my key own this data</i> with yes or no. This answers <i>who else is
/// here</i> — which machine, which environment, which key, which schema version — so a conflict comes with
/// names instead of leaving an operator to guess which of two deployments is the odd one out. It also makes
/// the legitimate case visible and boring: a preview beside a production install, both on the same key, is
/// exactly what a shared database is supposed to look like.</para>
///
/// <para>Diagnostic by nature: nothing depends on these rows being complete or current, and a stale row from
/// a decommissioned install ages out of the comparison rather than raising an alarm forever.</para>
/// </summary>
public sealed class KeywardInstallation
{
    public Guid Id { get; private set; }

    /// <summary>
    /// What makes an installation distinct: machine, environment and application. Two deployments on one
    /// server differ by environment, the same deployment on two servers by machine — and a redeploy of the
    /// same install must update its row rather than add one, which is why this is a unique natural key.
    /// </summary>
    public string InstallationKey { get; private set; }

    public string MachineName { get; private set; }
    public string EnvironmentName { get; private set; }
    public string ApplicationName { get; private set; }

    /// <summary>
    /// The key id this installation runs with. Since ids carry the key's fingerprint, two rows that differ
    /// here are two installations writing the same database under different keys — the condition the canary
    /// blocks, named.
    /// </summary>
    public string KekId { get; private set; }

    /// <summary>Where the host keeps its key, when it chose to publish that. Diagnostic only — the library never reads a path.</summary>
    public string? KeyCustodyLocation { get; private set; }

    /// <summary>The last migration this installation had applied — so a preview running ahead of production is visible.</summary>
    public string? SchemaVersion { get; private set; }

    public DateTimeOffset FirstSeenAt { get; private set; }
    public DateTimeOffset LastSeenAt { get; private set; }

    public KeywardInstallation(
        Guid id,
        string installationKey,
        string machineName,
        string environmentName,
        string applicationName,
        string kekId,
        string? keyCustodyLocation,
        string? schemaVersion,
        DateTimeOffset firstSeenAt,
        DateTimeOffset lastSeenAt)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(installationKey);

        Id = id;
        InstallationKey = installationKey;
        MachineName = machineName ?? string.Empty;
        EnvironmentName = environmentName ?? string.Empty;
        ApplicationName = applicationName ?? string.Empty;
        KekId = kekId ?? string.Empty;
        KeyCustodyLocation = keyCustodyLocation;
        SchemaVersion = schemaVersion;
        FirstSeenAt = firstSeenAt;
        LastSeenAt = lastSeenAt;
    }

    public static string KeyFor(string machineName, string environmentName, string applicationName) =>
        $"{machineName}|{environmentName}|{applicationName}";

    /// <summary>Refreshes the mutable half on a restart; identity and first sighting stay put.</summary>
    public void Seen(string kekId, string? keyCustodyLocation, string? schemaVersion, DateTimeOffset at)
    {
        KekId = kekId ?? string.Empty;
        KeyCustodyLocation = keyCustodyLocation;
        SchemaVersion = schemaVersion;
        LastSeenAt = at;
    }
}
