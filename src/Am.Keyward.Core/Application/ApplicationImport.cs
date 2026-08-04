using System.Text.Json;
using Am.Keyward.Core.Domain.ValueObjects;

namespace Am.Keyward.Core.Application;

/// <summary>One application in an import plan: its name and the secret keys to create (no values).</summary>
public sealed record ApplicationImportEntry(string Name, IReadOnlyList<string> Keys);

/// <summary>A problem found while parsing import input. Line is 1-based; 0 when no line is known (JSON).</summary>
public sealed record ImportParseError(int Line, string Message);

/// <summary>
/// The parsed result of an import input: the applications with their keys (the valid part) and every
/// parse/validation error. An import may only run when <see cref="Errors"/> is empty.
/// </summary>
public sealed record ApplicationImportPlan(
    IReadOnlyList<ApplicationImportEntry> Applications,
    IReadOnlyList<ImportParseError> Errors)
{
    public bool IsValid => Errors.Count == 0;
}

/// <summary>One application of an import preview: whether it exists and how each key would fare.</summary>
public sealed record ApplicationImportPreviewEntry(string Name, bool Exists, IReadOnlyList<ApplicationImportPreviewKey> Keys);

/// <summary>One key of an import preview; an existing key is skipped by the import (never touched).</summary>
public sealed record ApplicationImportPreviewKey(string Key, bool Exists);

/// <summary>What an import plan would do against the current state.</summary>
public sealed record ApplicationImportPreview(IReadOnlyList<ApplicationImportPreviewEntry> Applications)
{
    public int NewApplications => Applications.Count(a => !a.Exists);
    public int NewKeys => Applications.Sum(a => a.Keys.Count(k => !k.Exists));
    public int SkippedKeys => Applications.Sum(a => a.Keys.Count(k => k.Exists));
}

/// <summary>The outcome of an executed import.</summary>
public sealed record ApplicationImportResult(int ApplicationsCreated, int SecretsCreated, int SecretsSkipped);

/// <summary>
/// Bulk import of applications and secret KEYS (never values): additive and idempotent — existing
/// applications are reused, existing keys are skipped, nothing is deleted or overwritten, so the same
/// input can be imported repeatedly without harm. New applications get the tenant's default environment
/// set (via the regular project creation, including its pending app tokens); new keys are created with
/// no value in any environment. Requires the software-operator role, like every software mutation.
/// </summary>
public interface IApplicationImportService
{
    /// <summary>Compares a plan against the current state without changing anything.</summary>
    Task<ApplicationImportPreview> PreviewAsync(Guid tenantId, ApplicationImportPlan plan, CancellationToken ct = default);

    /// <summary>Executes a valid plan. Throws when the plan has parse errors.</summary>
    Task<ApplicationImportResult> ImportAsync(Guid tenantId, ApplicationImportPlan plan, Guid? actorUserId, CancellationToken ct = default);
}

/// <summary>
/// Parses the import input into an <see cref="ApplicationImportPlan"/>. Never throws — every problem
/// becomes an <see cref="ImportParseError"/>. Three input forms, auto-detected:
/// <list type="bullet">
/// <item><description>Indented text: an unindented line names an application, indented lines below it are
/// its keys; blank lines and full-line <c>#</c> comments are ignored.</description></item>
/// <item><description>A JSON object mapping application names to arrays of key strings.</description></item>
/// <item><description>An appsettings.json (any other JSON object): its leaf paths are flattened to
/// <c>Section:Key</c> keys — the values are ignored and never stored. Because the file itself carries no
/// application name, the caller must supply <c>fallbackApplicationName</c>.</description></item>
/// </list>
/// </summary>
public static class ApplicationImportParser
{
    public static ApplicationImportPlan Parse(string? text, string? fallbackApplicationName = null)
    {
        var applications = new List<MutableEntry>();
        var errors = new List<ImportParseError>();

        if (string.IsNullOrWhiteSpace(text))
        {
            errors.Add(new ImportParseError(0, "Input is empty."));
            return Build(applications, errors);
        }

        if (text.TrimStart().StartsWith('{'))
        {
            ParseJson(text, fallbackApplicationName, applications, errors);
        }
        else
        {
            ParseText(text, applications, errors);
        }

        if (applications.Count == 0 && errors.Count == 0)
        {
            errors.Add(new ImportParseError(0, "No applications found in the input."));
        }

        return Build(applications, errors);
    }

    private sealed class MutableEntry(string name)
    {
        public string Name { get; } = name;
        public List<string> Keys { get; } = [];
    }

    private static ApplicationImportPlan Build(List<MutableEntry> applications, List<ImportParseError> errors) =>
        new(applications.Select(a => new ApplicationImportEntry(a.Name, a.Keys)).ToList(), errors);

    private static MutableEntry GetOrAddApplication(List<MutableEntry> applications, string name)
    {
        var existing = applications.FirstOrDefault(a => a.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
        if (existing is null)
        {
            existing = new MutableEntry(name);
            applications.Add(existing);
        }

        return existing;
    }

    private static void AddKey(MutableEntry application, string rawKey, int line, List<ImportParseError> errors)
    {
        string key;
        try
        {
            key = SecretKey.Create(rawKey).Value;
        }
        catch (ArgumentException ex)
        {
            errors.Add(new ImportParseError(line, ex.Message));
            return;
        }

        if (!application.Keys.Any(k => k.Equals(key, StringComparison.OrdinalIgnoreCase)))
        {
            application.Keys.Add(key);
        }
    }

    private static void ParseText(string text, List<MutableEntry> applications, List<ImportParseError> errors)
    {
        MutableEntry? current = null;
        var lines = text.Replace("\r\n", "\n").Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            var lineNumber = i + 1;
            var trimmed = line.Trim();
            if (trimmed.Length == 0 || trimmed.StartsWith('#'))
            {
                continue;
            }

            if (char.IsWhiteSpace(line[0]))
            {
                if (current is null)
                {
                    errors.Add(new ImportParseError(lineNumber, $"Key '{trimmed}' appears before any application name."));
                    continue;
                }

                AddKey(current, trimmed, lineNumber, errors);
            }
            else
            {
                current = GetOrAddApplication(applications, trimmed);
            }
        }
    }

    private static void ParseJson(string text, string? fallbackApplicationName, List<MutableEntry> applications, List<ImportParseError> errors)
    {
        JsonDocument document;
        try
        {
            // Comments/trailing commas are common in hand-maintained appsettings files — accept them.
            document = JsonDocument.Parse(text, new JsonDocumentOptions
            {
                CommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true,
            });
        }
        catch (JsonException ex)
        {
            errors.Add(new ImportParseError((int)((ex.LineNumber ?? -1) + 1), $"Invalid JSON: {ex.Message}"));
            return;
        }

        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                errors.Add(new ImportParseError(0, "The JSON root must be an object."));
                return;
            }

            // Shape detection: ALL top-level values are arrays -> the explicit application map;
            // anything else -> an appsettings.json whose leaf paths become the keys of ONE application.
            var properties = root.EnumerateObject().ToList();
            if (properties.Count > 0 && properties.All(p => p.Value.ValueKind == JsonValueKind.Array))
            {
                foreach (var property in properties)
                {
                    var application = GetOrAddApplication(applications, property.Name.Trim());
                    foreach (var element in property.Value.EnumerateArray())
                    {
                        if (element.ValueKind != JsonValueKind.String)
                        {
                            errors.Add(new ImportParseError(0, $"Application '{property.Name}': expected an array of key strings."));
                            continue;
                        }

                        AddKey(application, element.GetString()!, 0, errors);
                    }
                }

                return;
            }

            if (string.IsNullOrWhiteSpace(fallbackApplicationName))
            {
                errors.Add(new ImportParseError(0,
                    "The JSON looks like an appsettings.json — enter the target application name to import its keys."));
                return;
            }

            var target = GetOrAddApplication(applications, fallbackApplicationName.Trim());
            FlattenAppSettings(root, segments: [], target, errors);
        }
    }

    private static void FlattenAppSettings(JsonElement element, List<string> segments, MutableEntry target, List<ImportParseError> errors)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var property in element.EnumerateObject())
                {
                    segments.Add(property.Name);
                    FlattenAppSettings(property.Value, segments, target, errors);
                    segments.RemoveAt(segments.Count - 1);
                }

                break;
            case JsonValueKind.Array:
                var index = 0;
                foreach (var item in element.EnumerateArray())
                {
                    segments.Add(index.ToString());
                    FlattenAppSettings(item, segments, target, errors);
                    segments.RemoveAt(segments.Count - 1);
                    index++;
                }

                break;
            default:
                // A leaf (string/number/bool/null): its configuration path becomes the key; the VALUE is
                // deliberately dropped — this import never stores values.
                AddKey(target, string.Join(':', segments), 0, errors);
                break;
        }
    }
}
