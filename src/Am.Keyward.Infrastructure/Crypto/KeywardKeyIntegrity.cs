using Microsoft.Extensions.Options;

namespace Am.Keyward.Infrastructure.Crypto;

/// <summary>Outcome of the startup key-ownership check (see <see cref="KekCanaryService"/>).</summary>
public enum KekIntegrityStatus
{
    /// <summary>The check has not run yet, or could not run (database unreachable).</summary>
    Unknown = 0,

    /// <summary>The key this process holds unwrapped the canary — it owns this data.</summary>
    Ok = 1,

    /// <summary>There was no canary; this installation wrote it. A fresh database, or the first start after the upgrade.</summary>
    Created = 2,

    /// <summary>The canary exists and this key cannot open it. The data belongs to a DIFFERENT key.</summary>
    Conflict = 3,
}

/// <summary>What to do when the key does not own the data.</summary>
public enum KekConflictBehaviour
{
    /// <summary>Refuse to encrypt or decrypt (default). Keyward degrades to unavailable; nothing else is affected.</summary>
    Disable = 0,

    /// <summary>Log and carry on. For a deliberate migration window only — every value written meanwhile is unreadable to the other installation.</summary>
    Warn = 1,
}

public sealed class KeywardKeyIntegrityOptions
{
    public const string SectionName = "Keyward:KeyIntegrity";

    /// <summary>
    /// Default <see cref="KekConflictBehaviour.Disable"/>: on a conflict, continuing to write is the one
    /// action that makes the situation strictly worse — every new value is sealed under a key the other
    /// installation does not have, so the split grows with every save. Refusing keeps the damage at zero and
    /// makes the cause visible immediately.
    /// </summary>
    public KekConflictBehaviour OnConflict { get; set; } = KekConflictBehaviour.Disable;

    /// <summary>
    /// Where this host keeps its key, published into the installation registry for diagnosis only — the
    /// library never reads a path. Worth setting where two installations may share a database: seeing that
    /// both name the same directory is what turns "they happen to agree" into "they are configured to".
    /// </summary>
    public string? KeyCustodyLocation { get; set; }

    /// <summary>
    /// How long an installation counts as still running after its last start. A deployment that was
    /// decommissioned must stop raising questions, so its row ages out of the comparison instead of being
    /// deleted (the history stays readable on the status page).
    /// </summary>
    public int PeerStaleAfterDays { get; set; } = 30;
}

/// <summary>
/// Raised instead of encrypting or decrypting with a key that does not own the stored data.
/// </summary>
public sealed class KeywardKeyMismatchException(string message) : InvalidOperationException(message);

/// <summary>
/// The installation-wide verdict of the startup key-ownership check, consulted by the crypto path.
/// Singleton, written once at startup and read on every protect/unprotect.
/// </summary>
public sealed class KeywardKeyIntegrityState(IOptions<KeywardKeyIntegrityOptions> options)
{
    public KekIntegrityStatus Status { get; private set; } = KekIntegrityStatus.Unknown;

    /// <summary>Operator-facing explanation of a conflict (which key ids are involved, when the canary was written).</summary>
    public string? Detail { get; private set; }

    public void Record(KekIntegrityStatus status, string? detail = null)
    {
        Status = status;
        Detail = detail;
    }

    /// <summary>
    /// True only for a confirmed conflict under the default behaviour. An <see cref="KekIntegrityStatus.Unknown"/>
    /// verdict deliberately does NOT block: a database that was unreachable at startup is an availability
    /// problem, and turning it into a permanent refusal would take Keyward down for a reason that has nothing
    /// to do with key custody.
    /// </summary>
    public bool IsBlocked =>
        Status == KekIntegrityStatus.Conflict && options.Value.OnConflict == KekConflictBehaviour.Disable;

    public void ThrowIfBlocked()
    {
        if (IsBlocked)
        {
            throw new KeywardKeyMismatchException(
                "The key-encryption key this installation holds does not own the data in this database, so "
                + "encrypting or decrypting would produce values the other installation cannot read. "
                + (Detail ?? string.Empty));
        }
    }
}
