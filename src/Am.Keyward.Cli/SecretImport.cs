using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using Am.Keyward.Contracts;

namespace Am.Keyward.Cli;

/// <summary>One value found in the source file and where it goes.</summary>
internal sealed record ImportRow(int Line, string Application, string Environment, string Key, string Value);

/// <summary>What an import would write, and everything that stops it.</summary>
internal sealed record ImportPlan(IReadOnlyList<ImportRow> Rows, IReadOnlyList<string> Problems);

/// <summary>
/// `keyward import` (decision T30 A): moves a plain-text secrets file into application keys without the values passing
/// through an AI agent. A mapping file — no values in it, so an agent may write it — names, per entry, a regular
/// expression that must match exactly ONE line of the source and capture the value (group <c>value</c>), and the
/// application, environment and key it goes to. Nothing is guessed: an entry matching no line or several lines stops
/// the whole import before anything is written.
/// <code>
/// { "entries": [ { "pattern": "^PRTG API token: `(?&lt;value&gt;[^`]+)`$", "application": "Ops.Prtg",
///                  "environment": "Production", "key": "Prtg:ApiToken" } ] }
/// </code>
/// Writing goes through the agent API with the agent token `amkeyward-mcp setup` stored; the token needs «Manage
/// applications» and must reach the application.
/// </summary>
internal static class SecretImport
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public static ImportPlan Plan(string mappingJson, IReadOnlyList<string> sourceLines)
    {
        Mapping? mapping;
        try
        {
            mapping = JsonSerializer.Deserialize<Mapping>(mappingJson, Json);
        }
        catch (JsonException ex)
        {
            return new ImportPlan([], [$"The mapping is not valid JSON: {ex.Message}"]);
        }

        var rows = new List<ImportRow>();
        var problems = new List<string>();
        var entries = mapping?.Entries ?? [];
        if (entries.Count == 0)
        {
            problems.Add("The mapping has no entries.");
        }

        for (var i = 0; i < entries.Count; i++)
        {
            var entry = entries[i];
            var label = $"entry {i + 1} ({entry.Application}/{entry.Environment}/{entry.Key})";
            if (string.IsNullOrWhiteSpace(entry.Pattern) || string.IsNullOrWhiteSpace(entry.Application)
                || string.IsNullOrWhiteSpace(entry.Environment) || string.IsNullOrWhiteSpace(entry.Key))
            {
                problems.Add($"{label}: pattern, application, environment and key are all required.");
                continue;
            }

            Regex regex;
            try
            {
                regex = new Regex(entry.Pattern, RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
            }
            catch (ArgumentException ex)
            {
                problems.Add($"{label}: the pattern is not a valid regular expression ({ex.Message}).");
                continue;
            }

            var matches = sourceLines
                .Select((line, index) => (Line: index + 1, Match: regex.Match(line)))
                .Where(m => m.Match.Success)
                .ToList();
            if (matches.Count != 1)
            {
                problems.Add(matches.Count == 0
                    ? $"{label}: the pattern matches no line."
                    : $"{label}: the pattern matches {matches.Count} lines ({string.Join(", ", matches.Select(m => m.Line))}) - make it match exactly one.");
                continue;
            }

            var (lineNumber, match) = matches[0];
            var group = match.Groups["value"].Success ? match.Groups["value"] : match.Groups.Count > 1 ? match.Groups[1] : null;
            if (group is null || group.Value.Length == 0)
            {
                problems.Add($"{label}: line {lineNumber} matches, but the pattern captures no value - use a group (?<value>...).");
                continue;
            }

            rows.Add(new ImportRow(lineNumber, entry.Application.Trim(), entry.Environment.Trim(), entry.Key.Trim(), group.Value));
        }

        foreach (var duplicate in rows.GroupBy(r => (r.Application.ToLowerInvariant(), r.Environment.ToLowerInvariant(), r.Key.ToLowerInvariant())).Where(g => g.Count() > 1))
        {
            problems.Add($"{duplicate.First().Application}/{duplicate.First().Environment}/{duplicate.First().Key} is mapped more than once (lines {string.Join(", ", duplicate.Select(r => r.Line))}).");
        }

        return new ImportPlan(rows, problems);
    }

    /// <summary>Writes the rows through the agent API; prints one line per row (never a value). Returns how many were written.</summary>
    public static async Task<int> WriteAsync(HttpClient http, IReadOnlyList<ImportRow> rows, bool overwrite, TextWriter output)
    {
        var applications = await GetApplicationsAsync(http);
        var written = 0;
        foreach (var row in rows)
        {
            var application = applications.FirstOrDefault(a => string.Equals(a.Name, row.Application, StringComparison.OrdinalIgnoreCase))
                ?? throw new KeywardCliException(KeywardExitCode.Failed,
                    $"line {row.Line}: the agent token cannot reach an application '{row.Application}' - create it, or add it to the token's applications.");

            var key = application.Keys.FirstOrDefault(k => string.Equals(k.Key, row.Key, StringComparison.OrdinalIgnoreCase));
            var state = key?.Values.FirstOrDefault(v => string.Equals(v.Environment, row.Environment, StringComparison.OrdinalIgnoreCase));
            var target = $"{application.Name} / {row.Environment} / {row.Key}";

            if (key is null)
            {
                using var response = await http.PostAsJsonAsync(
                    AgentPath($"applications/{application.Id}/secrets"), new AgentCreateSecretRequest(row.Key, row.Environment, row.Value), Json);
                await EnsureAsync(response, row);
                output.WriteLine($"line {row.Line}: {target} - created");
                written++;
                continue;
            }

            if (state is { ValueSet: true } && !overwrite)
            {
                output.WriteLine($"line {row.Line}: {target} - already has a value, skipped (use --overwrite to replace it)");
                continue;
            }

            using var request = new HttpRequestMessage(HttpMethod.Put, AgentPath($"applications/{application.Id}/secrets/{Uri.EscapeDataString(key.Key)}"))
            {
                Content = JsonContent.Create(new AgentSetSecretValueRequest(row.Environment, row.Value), options: Json),
            };
            if (state is { ValueSet: true, VersionId: { } version })
            {
                request.Headers.IfMatch.Add(new EntityTagHeaderValue($"\"{version}\""));
            }
            else
            {
                request.Headers.IfNoneMatch.Add(EntityTagHeaderValue.Any);
            }

            using var put = await http.SendAsync(request);
            await EnsureAsync(put, row);
            output.WriteLine($"line {row.Line}: {target} - {(state is { ValueSet: true } ? "replaced" : "set")}");
            written++;
        }

        return written;
    }

    private static async Task<List<AgentApplicationResponse>> GetApplicationsAsync(HttpClient http)
    {
        using var response = await http.GetAsync(AgentPath("applications"));
        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            throw new KeywardCliException(KeywardExitCode.TokenRejected, "Keyward rejected the AI agent token (unknown, revoked or expired).");
        }

        if (response.StatusCode == HttpStatusCode.Forbidden)
        {
            throw new KeywardCliException(KeywardExitCode.NetworkNotAllowed,
                "The AI agent token may not manage applications, or this network may not use the agent API.");
        }

        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<List<AgentApplicationResponse>>(Json) ?? [];
    }

    private static async Task EnsureAsync(HttpResponseMessage response, ImportRow row)
    {
        if (response.IsSuccessStatusCode)
        {
            return;
        }

        var detail = await response.Content.ReadAsStringAsync();
        throw new KeywardCliException(KeywardExitCode.Failed,
            $"line {row.Line}: Keyward answered {(int)response.StatusCode} for {row.Application}/{row.Environment}/{row.Key} - {Title(detail)}. Rows before it were written.");
    }

    private static string Title(string problemJson)
    {
        try
        {
            using var document = JsonDocument.Parse(problemJson);
            return document.RootElement.TryGetProperty("title", out var title) ? title.GetString() ?? "" : "";
        }
        catch (JsonException)
        {
            return "";
        }
    }

    private static string AgentPath(string relative) => $"{KeywardApiDefaults.BasePath.TrimEnd('/')}/agent/{relative}";

    private sealed record Mapping(List<MappingEntry>? Entries);

    private sealed record MappingEntry(string Pattern, string Application, string Environment, string Key);
}
