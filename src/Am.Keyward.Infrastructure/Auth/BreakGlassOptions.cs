using Microsoft.Extensions.Hosting;

namespace Am.Keyward.Infrastructure.Auth;

/// <summary>
/// Configuration for the break-glass mechanism and the other out-of-band trail that lives next to it.
/// <see cref="SinkFilePath"/> is the append-only file the non-repudiable break-glass trail is written to — it
/// should live outside the application database and ideally on storage the database admin cannot rewrite
/// (separate host/permissions). <see cref="ValidityMinutes"/> is how long an approved grant may be consumed
/// before it expires. <see cref="AuditAnchorFilePath"/> receives the audit-chain head anchors.
/// </summary>
public sealed class BreakGlassOptions
{
    public const string SectionName = "Keyward:BreakGlass";

    /// <summary>The file name used when the path is not configured (Development only) and next to which the anchors go.</summary>
    public const string DefaultSinkFileName = "breakglass-audit.jsonl";

    /// <summary>The file name of the audit head anchors, placed next to the break-glass trail by default.</summary>
    public const string DefaultAuditAnchorFileName = "audit-anchors.jsonl";

    /// <summary>
    /// Absolute path to the append-only break-glass file. REQUIRED outside Development (the host fails to start
    /// without it); in Development it defaults to <see cref="DefaultSinkFileName"/> in the working directory. A host
    /// may set it in configuration or in code (<c>PostConfigure&lt;BreakGlassOptions&gt;</c>) — both are honoured.
    /// </summary>
    public string? SinkFilePath { get; set; }

    /// <summary>Validity window (minutes) of an approved grant. Default 60.</summary>
    public int ValidityMinutes { get; set; } = 60;

    /// <summary>
    /// Whether the ops monitor writes the audit chains' heads to the out-of-band anchor file and the audit-chain
    /// verifier fails when the database is behind a recorded anchor (entries deleted from the end, or the database
    /// restored to an older state). Default <c>true</c>; it is active only when an anchor path resolves
    /// (<see cref="ResolveAuditAnchorFilePath"/>).
    /// </summary>
    public bool AuditAnchorsEnabled { get; set; } = true;

    /// <summary>
    /// Where the audit head anchors are written. Default: <see cref="DefaultAuditAnchorFileName"/> in the folder of
    /// <see cref="SinkFilePath"/> — the same out-of-band storage. Without either, anchoring is off.
    /// </summary>
    public string? AuditAnchorFilePath { get; set; }

    /// <summary>
    /// The break-glass trail's path: <see cref="SinkFilePath"/> when set; in Development (or when
    /// <paramref name="environment"/> says Development) <see cref="DefaultSinkFileName"/> in the working directory;
    /// otherwise an <see cref="InvalidOperationException"/> that says what to configure.
    /// </summary>
    /// <param name="environment">The host environment; <c>null</c> (no host) is treated as not Development.</param>
    public string ResolveSinkFilePath(IHostEnvironment? environment)
    {
        if (!string.IsNullOrWhiteSpace(SinkFilePath))
        {
            return Path.GetFullPath(SinkFilePath);
        }

        if (environment?.IsDevelopment() == true)
        {
            return Path.Combine(Directory.GetCurrentDirectory(), DefaultSinkFileName);
        }

        throw new InvalidOperationException(MissingSinkFilePathMessage(environment));
    }

    /// <summary>
    /// The anchor file's path, or <c>null</c> when anchoring is off: disabled, or neither
    /// <see cref="AuditAnchorFilePath"/> nor <see cref="SinkFilePath"/> is configured.
    /// </summary>
    public string? ResolveAuditAnchorFilePath()
    {
        if (!AuditAnchorsEnabled)
        {
            return null;
        }

        if (!string.IsNullOrWhiteSpace(AuditAnchorFilePath))
        {
            return Path.GetFullPath(AuditAnchorFilePath);
        }

        if (string.IsNullOrWhiteSpace(SinkFilePath))
        {
            return null;
        }

        string? folder = Path.GetDirectoryName(Path.GetFullPath(SinkFilePath));
        return folder is null ? null : Path.Combine(folder, DefaultAuditAnchorFileName);
    }

    internal static string MissingSinkFilePathMessage(IHostEnvironment? environment) =>
        $"KEYWARD: {SectionName}:SinkFilePath is not set (environment '{environment?.EnvironmentName ?? "unknown"}'). "
        + "The break-glass trail must be written to an explicit, durable path outside the deployed application folder "
        + "and ideally on storage the database administrator cannot rewrite, e.g. "
        + @"'C:\ProgramData\<Company>\Keyward\breakglass-audit.jsonl'. Set it in configuration "
        + $"({SectionName}:SinkFilePath) or in code (PostConfigure<BreakGlassOptions>). Only Development falls back to "
        + "the working directory.";
}
