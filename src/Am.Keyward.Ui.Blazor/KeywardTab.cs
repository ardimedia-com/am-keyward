namespace Am.Keyward.Ui.Blazor;

/// <summary>One tab for <see cref="KeywardTabBar"/>: a stable key, a visible label, an optional Lucide icon
/// name and an optional numeric badge.</summary>
public sealed record KeywardTab(string Key, string Label, string? Icon = null, int? Badge = null);
