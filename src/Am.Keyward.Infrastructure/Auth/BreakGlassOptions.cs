namespace Am.Keyward.Infrastructure.Auth;

/// <summary>
/// Configuration for the break-glass mechanism. <see cref="SinkFilePath"/> is the out-of-band, append-only
/// file the non-repudiable break-glass trail is written to — it should live outside the application
/// database and ideally on storage the database admin cannot rewrite (separate host/permissions).
/// <see cref="ValidityMinutes"/> is how long an approved grant may be consumed before it expires.
/// </summary>
public sealed class BreakGlassOptions
{
    public const string SectionName = "Keyward:BreakGlass";

    /// <summary>Absolute path to the append-only break-glass file. Defaults to <c>breakglass-audit.jsonl</c> in the working directory.</summary>
    public string? SinkFilePath { get; set; }

    /// <summary>Validity window (minutes) of an approved grant. Default 60.</summary>
    public int ValidityMinutes { get; set; } = 60;
}
