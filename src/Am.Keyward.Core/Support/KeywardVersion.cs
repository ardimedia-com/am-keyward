using System.Reflection;

namespace Am.Keyward.Core.Support;

/// <summary>
/// The version of the loaded Keyward assemblies, for display on host status/about pages. Read from the
/// <see cref="AssemblyInformationalVersionAttribute"/> that the SDK derives from the package version, so it
/// always reflects the assemblies actually loaded — a local ProjectReference build and a restored NuGet
/// package both report their true version without any manually maintained constant.
/// </summary>
public static class KeywardVersion
{
    /// <summary>The semantic version of the loaded Keyward assemblies, e.g. "0.6.0-preview".</summary>
    public static string Current { get; } = ReadInformationalVersion();

    private static string ReadInformationalVersion()
    {
        string? raw = typeof(KeywardVersion).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (string.IsNullOrWhiteSpace(raw))
        {
            return "unknown";
        }

        // SourceLink appends "+<commit-sha>" build metadata; strip it down to the readable SemVer.
        int plus = raw.IndexOf('+', StringComparison.Ordinal);
        return plus < 0 ? raw : raw[..plus];
    }
}
