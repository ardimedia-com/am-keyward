namespace Am.Keyward.Cli;

/// <summary>A small, strict command-line parser: unknown options are errors, never silently ignored.</summary>
internal sealed class Options
{
    private readonly List<string> positional = [];
    private readonly HashSet<string> flags = new(StringComparer.Ordinal);
    private readonly Dictionary<string, List<string>> values = new(StringComparer.Ordinal);

    public static Options Parse(string[] args, string[]? flags = null, string[]? values = null, string[]? repeatable = null)
    {
        var options = new Options();
        var knownFlags = new HashSet<string>(flags ?? [], StringComparer.Ordinal);
        var single = new HashSet<string>(values ?? [], StringComparer.Ordinal);
        var many = new HashSet<string>(repeatable ?? [], StringComparer.Ordinal);

        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            if (!arg.StartsWith("--", StringComparison.Ordinal))
            {
                options.positional.Add(arg);
                continue;
            }

            if (knownFlags.Contains(arg))
            {
                options.flags.Add(arg);
                continue;
            }

            if (!single.Contains(arg) && !many.Contains(arg))
            {
                throw new KeywardCliException(KeywardExitCode.Usage, $"Unknown option '{arg}'. Run 'keyward help'.");
            }

            if (i + 1 >= args.Length)
            {
                throw new KeywardCliException(KeywardExitCode.Usage, $"'{arg}' needs a value.");
            }

            if (single.Contains(arg) && options.values.ContainsKey(arg))
            {
                throw new KeywardCliException(KeywardExitCode.Usage, $"'{arg}' may be given once.");
            }

            (options.values.TryGetValue(arg, out var list) ? list : options.values[arg] = []).Add(args[++i]);
        }

        return options;
    }

    public string Positional(int index, string usage) =>
        index < positional.Count ? positional[index] : throw new KeywardCliException(KeywardExitCode.Usage, usage);

    public bool Has(string flag) => flags.Contains(flag);

    public string? Value(string name) => values.TryGetValue(name, out var list) ? list[0] : null;

    public IReadOnlyList<string> Values(string name) => values.TryGetValue(name, out var list) ? list : [];

    public Uri Uri(string name) =>
        Value(name) is { } text && System.Uri.TryCreate(text, UriKind.Absolute, out var uri) && uri.Scheme is "https" or "http"
            ? uri
            : throw new KeywardCliException(KeywardExitCode.Usage, $"{name} needs the installation's address, e.g. https://keyward.example.com");
}
