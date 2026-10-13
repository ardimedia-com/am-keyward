using System.Reflection;

namespace Am.Keyward.Cli;

/// <summary>
/// Writes the PowerShell SecretManagement vault (embedded in this program) into a PowerShell modules folder, so one
/// install of `keyward` brings both. The module calls `keyward` for every read — no second credential store.
/// </summary>
internal static class PowerShellModule
{
    public const string Name = "Am.Keyward.SecretManagement";

    private const string ResourcePrefix = "PowerShell/" + Name + "/";

    /// <summary>The user module folder: PowerShell 7 (<c>Documents\PowerShell\Modules</c>), Windows PowerShell 5.1, or XDG elsewhere.</summary>
    public static string DefaultModulesFolder(bool windowsPowerShell)
    {
        if (OperatingSystem.IsWindows())
        {
            var documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            return Path.Combine(documents, windowsPowerShell ? "WindowsPowerShell" : "PowerShell", "Modules");
        }

        var data = Environment.GetEnvironmentVariable("XDG_DATA_HOME") is { Length: > 0 } xdg
            ? xdg
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "share");
        return Path.Combine(data, "powershell", "Modules");
    }

    /// <summary>Writes (or replaces) the module under <paramref name="modulesFolder"/>; returns its folder.</summary>
    public static string Install(string modulesFolder)
    {
        var assembly = typeof(PowerShellModule).Assembly;
        var target = Path.Combine(modulesFolder, Name);
        var version = ModuleVersion(assembly);
        // %(RecursiveDir) carries the build machine's separator into the resource name; compare with «/» only.
        var resources = assembly.GetManifestResourceNames()
            .Select(r => (Name: r, Path: r.Replace('\\', '/')))
            .Where(r => r.Path.StartsWith(ResourcePrefix, StringComparison.Ordinal))
            .ToList();
        if (resources.Count == 0)
        {
            throw new KeywardCliException(KeywardExitCode.Failed, "The PowerShell module is missing from this program.");
        }

        foreach (var resource in resources)
        {
            var path = Path.Combine(target, resource.Path[ResourcePrefix.Length..].Replace('/', Path.DirectorySeparatorChar));
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            using var stream = assembly.GetManifestResourceStream(resource.Name)!;
            using var reader = new StreamReader(stream);
            File.WriteAllText(path, reader.ReadToEnd().Replace("{{VERSION}}", version, StringComparison.Ordinal), new System.Text.UTF8Encoding(true));
        }

        return target;
    }

    // ModuleVersion accepts only a plain version (no «-preview»).
    private static string ModuleVersion(Assembly assembly)
    {
        var version = assembly.GetName().Version ?? new Version(0, 0, 0);
        return $"{version.Major}.{version.Minor}.{Math.Max(version.Build, 0)}";
    }
}
