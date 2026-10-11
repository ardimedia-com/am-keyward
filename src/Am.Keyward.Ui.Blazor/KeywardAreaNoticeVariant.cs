namespace Am.Keyward.Ui.Blazor;

/// <summary>
/// What the <see cref="KeywardArea.Notice"/> in an area's title means — decides its colour. Same vocabulary and
/// colours as the Keyward UI's badges (<c>.badge</c>, <c>.badge-success</c>, <c>.badge-warning</c>, <c>.badge-danger</c>).
/// </summary>
public enum KeywardAreaNoticeVariant
{
    /// <summary>Neutral information that needs no action (the plain, muted badge).</summary>
    Info,

    /// <summary>Something went well.</summary>
    Success,

    /// <summary>Something inside needs attention (the default).</summary>
    Warning,

    /// <summary>Something inside is broken or failed.</summary>
    Danger,
}
