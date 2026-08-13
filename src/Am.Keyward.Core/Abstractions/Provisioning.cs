namespace Am.Keyward.Core.Abstractions;

/// <summary>How a single provisioning check came out.</summary>
public enum KeywardCheckState
{
    /// <summary>Configured and working.</summary>
    Ok,

    /// <summary>Works, but something is worth knowing (e.g. a fallback is in use).</summary>
    Warning,

    /// <summary>Not configured / not reachable — Keyward cannot run like this.</summary>
    Missing,
}

/// <summary>Whether Keyward is meant to be running in a given environment — the host's own policy.</summary>
public enum KeywardExpectation
{
    /// <summary>On or off, both fine — never flagged. Typically Development.</summary>
    Optional,

    /// <summary>Deliberately off here; "off" is the correct state, not a finding.</summary>
    ExpectedOff,

    /// <summary>MUST be on and provisioned; off here is a real gap.</summary>
    Required,
}

/// <summary>
/// The provisioning points, in the order an operator works through them. The id is what a UI resolves a
/// title, a requirement and a location text from — the diagnostics themselves carry no prose, so the same
/// check can be rendered in any language.
/// </summary>
public enum KeywardCheckId
{
    /// <summary>The host's master switch for the embedded Keyward.</summary>
    FeatureSwitch,

    /// <summary>The key-encryption key file (where the host uses file-based custody).</summary>
    KekFile,

    /// <summary>The connection string that points at the database holding the <c>amkeyward</c> schema.</summary>
    ConnectionString,

    /// <summary>Whether that connection actually opens.</summary>
    DatabaseReachable,

    /// <summary>Whether the <c>amkeyward</c> schema exists and carries applied migrations.</summary>
    Schema,

    /// <summary>Whether the host's tenant row has been seeded.</summary>
    Tenant,
}

/// <summary>
/// WHY a check came out the way it did — the discriminator a UI turns into a sentence (and a fix hint), so
/// that adding a language never means touching the probing logic.
/// </summary>
public enum KeywardCheckOutcome
{
    /// <summary>Everything as it should be.</summary>
    Ok,

    /// <summary>Switched off, and that is acceptable in this environment.</summary>
    FeatureOffAcceptable,

    /// <summary>Switched off although this environment requires it — a gap to close.</summary>
    FeatureOffRequired,

    /// <summary>The KEK file does not exist yet (it is created on the first start).</summary>
    KekMissing,

    /// <summary>The host uses a key provider other than the packaged file custody — nothing to check here.</summary>
    KekNotFileBased,

    /// <summary>No connection string configured.</summary>
    ConnectionMissing,

    /// <summary>Configured but not parseable.</summary>
    ConnectionUnreadable,

    /// <summary>Configured with Integrated Security outside Development, where a least-privilege login is expected.</summary>
    ConnectionIntegratedSecurityOutsideDevelopment,

    /// <summary>The connection could not be opened.</summary>
    DatabaseUnreachable,

    /// <summary>The schema does not exist in this database.</summary>
    SchemaMissing,

    /// <summary>The schema exists but no migration has been applied.</summary>
    SchemaNoMigrations,

    /// <summary>The migration state could not be read (usually a permission problem).</summary>
    SchemaUnreadable,

    /// <summary>The tenant row has not been seeded.</summary>
    TenantMissing,

    /// <summary>The tenant row could not be read (usually a permission problem).</summary>
    TenantUnreadable,

    /// <summary>Not probed, because an earlier prerequisite is missing.</summary>
    NotProbed,
}

/// <summary>
/// One provisioning check: which point it is, how it came out, why, and the concrete technical value behind
/// it. Deliberately prose-free — see <see cref="KeywardCheckOutcome"/>.
/// </summary>
/// <param name="Id">Which point this is.</param>
/// <param name="State">Outcome, for the icon and the overall verdict.</param>
/// <param name="Outcome">Why — what a UI turns into a sentence.</param>
/// <param name="Technical">The concrete value(s): a path, server/database/login, the migration count, the
/// tenant. NEVER a secret — a connection string is reduced to server, database and login.</param>
/// <param name="Error">The provider's own message when a probe failed; shown verbatim because it is what an
/// operator needs, and it is not translatable.</param>
public sealed record KeywardCheck(
    KeywardCheckId Id,
    KeywardCheckState State,
    KeywardCheckOutcome Outcome,
    string? Technical = null,
    string? Error = null);

/// <summary>
/// Diagnoses whether Keyward is provisioned in the environment the host is running in. The port lives here so
/// a UI can render the report without depending on the persistence layer that produces it.
/// </summary>
public interface IKeywardProvisioningStatus
{
    /// <summary>The host's master switch — the diagnostics exist to explain an environment where it is off.</summary>
    bool Enabled { get; }

    /// <summary>Name of the running environment, so a page can say which install it describes.</summary>
    string EnvironmentName { get; }

    /// <summary>Whether Keyward is meant to run here (the host's policy).</summary>
    KeywardExpectation Expectation { get; }

    /// <summary>The settings file carrying this environment's values, to tell the operator what to edit.</summary>
    string SettingsFile { get; }

    /// <summary>The configuration key of the runtime connection string.</summary>
    string ConnectionStringName { get; }

    /// <summary>The full path of the KEK file, or <c>null</c> when the host does not use file custody.</summary>
    string? KekPath { get; }

    /// <summary>Server / database of the Keyward connection — never the raw string, which may carry a password.</summary>
    string? DatabaseLabel { get; }

    /// <summary>Runs every check. Never throws: a failed probe becomes a check that says so.</summary>
    Task<IReadOnlyList<KeywardCheck>> RunAsync(CancellationToken cancellationToken = default);
}

/// <summary>Convenience over a check list.</summary>
public static class KeywardCheckExtensions
{
    /// <summary>True when every check passed — what a green/amber banner hangs off.</summary>
    public static bool AllOk(this IReadOnlyList<KeywardCheck> checks) =>
        checks.All(c => c.State == KeywardCheckState.Ok);
}
