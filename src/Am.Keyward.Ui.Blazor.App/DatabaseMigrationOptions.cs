namespace Am.Keyward.Ui.Blazor.App;

/// <summary>
/// Options for the runtime migration safety-net. The app migrates on startup; this periodic check covers
/// the case where the database is swapped/refreshed/restored under a running instance (e.g. a nightly
/// production copy into a test environment), where the startup migration would otherwise be bypassed.
/// </summary>
public sealed class DatabaseMigrationOptions
{
    public const string SectionName = "DatabaseMigration";

    /// <summary>Master switch for the periodic safety-net (the startup migration always runs).</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>How often to re-check for pending migrations (floored at 10 seconds).</summary>
    public int CheckIntervalSeconds { get; set; } = 60;
}
