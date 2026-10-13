using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Reflection;
using System.Text.Json;
using System.Text.RegularExpressions;
using Am.Keyward.Client;
using Am.Keyward.Contracts;

namespace Am.Keyward.Cli;

/// <summary>What the commands need from the outside world — replaced in tests.</summary>
internal sealed class KeywardCliContext
{
    public required TextWriter Out { get; init; }
    public required TextWriter Err { get; init; }
    public required TextReader In { get; init; }
    public required KeywardProfiles Profiles { get; init; }

    /// <summary>An HTTP client for an installation with a Bearer token and a timeout; base address = installation root.</summary>
    public required Func<Uri, string, TimeSpan, HttpClient> HttpClientFor { get; init; }

    /// <summary>Reads a token typed or pasted at the console without echoing it.</summary>
    public required Func<string> ReadHiddenToken { get; init; }

    /// <summary>True when stdin is a pipe or a file (then a token is read from it, not from the keyboard).</summary>
    public required bool InputRedirected { get; init; }

    /// <summary>The agent token stored by `amkeyward-mcp setup` for an installation (for `import`), or null.</summary>
    public required Func<Uri, string?> AgentTokenFor { get; init; }

    /// <summary>Starts a program and returns its exit code.</summary>
    public required Func<ProcessStartInfo, Task<int>> RunProcess { get; init; }

    /// <summary>The folder PowerShell loads user modules from (PowerShell 7, or Windows PowerShell 5.1 when asked).</summary>
    public required Func<bool, string> PowerShellModulesFolder { get; init; }
}

/// <summary>
/// The `keyward` commands (decisions T18–T23, T30). Scripts and tools read secrets through the software-client API with
/// an app token per profile; values go to stdout (`get`), into one child process (`run`), into Claude Code's request
/// headers (`headers`) or into one shell session (`env`) — never into an AI agent's own process, and never onto a
/// command line. Every failure ends with a <see cref="KeywardExitCode"/> and a one-line reason on stderr.
/// </summary>
internal sealed class KeywardCli(KeywardCliContext context)
{
    // headersHelper gives up after 10 s; a lookup must answer well inside that.
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan ImportTimeout = TimeSpan.FromSeconds(30);
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public async Task<int> RunAsync(string[] args)
    {
        try
        {
            var command = args.FirstOrDefault()?.ToLowerInvariant();
            var rest = args.Skip(1).ToArray();
            return (int)await (command switch
            {
                "login" => LoginAsync(rest),
                "logout" => Task.FromResult(Logout(rest)),
                "profiles" => Task.FromResult(ListProfiles()),
                "get" => GetAsync(rest),
                "keys" => KeysAsync(rest),
                "run" => RunProgramAsync(rest),
                "headers" => HeadersAsync(rest),
                "env" => EnvAsync(rest),
                "import" => ImportAsync(rest),
                "powershell" => Task.FromResult(PowerShell(rest)),
                "--version" or "version" => Task.FromResult(Version()),
                null or "help" or "--help" or "-h" or "/?" => Task.FromResult(Help()),
                _ => throw new KeywardCliException(KeywardExitCode.Usage, $"Unknown command '{args[0]}'. Run 'keyward help'."),
            });
        }
        catch (KeywardCliException ex)
        {
            context.Err.WriteLine($"keyward: {ex.Message}");
            return (int)ex.Code;
        }
        catch (TaskCanceledException)
        {
            context.Err.WriteLine("keyward: Keyward did not answer in time.");
            return (int)KeywardExitCode.Unreachable;
        }
        catch (HttpRequestException ex) when (ex.StatusCode is null)
        {
            context.Err.WriteLine($"keyward: Keyward cannot be reached ({ex.Message}).");
            return (int)KeywardExitCode.Unreachable;
        }
        catch (HttpRequestException ex)
        {
            context.Err.WriteLine($"keyward: Keyward answered {(int)ex.StatusCode!} ({ex.Message}).");
            return (int)KeywardExitCode.Failed;
        }
    }

    // --- profiles ---

    private async Task<KeywardExitCode> LoginAsync(string[] args)
    {
        var options = Options.Parse(args, flags: ["--token-stdin"], values: ["--service"]);
        var name = options.Positional(0, "keyward login <profile> --service https://keyward.example.com");
        var service = options.Uri("--service");

        string token;
        if (options.Has("--token-stdin") || context.InputRedirected)
        {
            token = (await context.In.ReadToEndAsync()).Trim();
        }
        else
        {
            context.Err.Write("Paste the app token (shown as *) and press Enter: ");
            token = context.ReadHiddenToken();
            context.Err.WriteLine();
        }

        if (token.StartsWith("amkwa_", StringComparison.Ordinal))
        {
            throw new KeywardCliException(KeywardExitCode.Usage,
                "That is an AI agent token - it belongs to 'amkeyward-mcp setup'. keyward needs an app token (amkw_...), issued under Applications -> Tokens.");
        }

        if (!token.StartsWith("amkw_", StringComparison.Ordinal))
        {
            throw new KeywardCliException(KeywardExitCode.Usage, "That is not an app token (it starts with amkw_). Nothing was stored.");
        }

        context.Err.WriteLine($"Received {KeywardTokenInput.Mask(token)} ({token.Length} characters).");

        using var http = context.HttpClientFor(service, token, RequestTimeout);
        using var response = await http.GetAsync(ClientPath("ping"));
        ThrowForAccess(response.StatusCode);
        response.EnsureSuccessStatusCode();

        var place = context.Profiles.Save(name, service, token);
        context.Err.WriteLine($"Profile '{name.ToLowerInvariant()}' stored in {place} (for {service.GetLeftPart(UriPartial.Authority)}). Try: keyward keys {name.ToLowerInvariant()}");
        return KeywardExitCode.Ok;
    }

    private KeywardExitCode Logout(string[] args)
    {
        var name = Options.Parse(args).Positional(0, "keyward logout <profile>");
        context.Err.WriteLine(context.Profiles.Remove(name)
            ? $"Profile '{name}' removed from this computer. Revoke its app token in Keyward if it should stop working everywhere."
            : $"No profile '{name}' on this computer.");
        return KeywardExitCode.Ok;
    }

    private KeywardExitCode ListProfiles()
    {
        var profiles = context.Profiles.List();
        if (profiles.Count == 0)
        {
            context.Err.WriteLine("No profiles yet. Create one with: keyward login <profile> --service https://keyward.example.com");
            return KeywardExitCode.Ok;
        }

        foreach (var profile in profiles)
        {
            var token = context.Profiles.HasStoredToken(profile) ? "token stored" : "NO TOKEN";
            context.Out.WriteLine($"{profile.Name}\t{profile.ServiceUri.GetLeftPart(UriPartial.Authority)}\t{token}");
        }

        return KeywardExitCode.Ok;
    }

    // --- reading ---

    private async Task<KeywardExitCode> GetAsync(string[] args)
    {
        var options = Options.Parse(args, flags: ["--json"]);
        var reference = SecretReference.Parse(options.Positional(0, "keyward get <profile>:<key> [--json]"));
        var value = await LookupAsync(reference);
        context.Out.WriteLine(options.Has("--json")
            ? JsonSerializer.Serialize(new { key = reference.Key, value }, Json)
            : value);
        return KeywardExitCode.Ok;
    }

    private async Task<KeywardExitCode> KeysAsync(string[] args)
    {
        var options = Options.Parse(args, flags: ["--json"]);
        var profile = options.Positional(0, "keyward keys <profile> [--json]");
        var all = await ReadAllAsync(profile);
        var keys = all.Keys.Order(StringComparer.OrdinalIgnoreCase).ToList();
        if (options.Has("--json"))
        {
            context.Out.WriteLine(JsonSerializer.Serialize(keys, Json));
        }
        else
        {
            foreach (var key in keys)
            {
                context.Out.WriteLine(key);
            }
        }

        return KeywardExitCode.Ok;
    }

    private async Task<KeywardExitCode> RunProgramAsync(string[] args)
    {
        var separator = Array.IndexOf(args, "--");
        if (separator < 0 || separator == args.Length - 1)
        {
            throw new KeywardCliException(KeywardExitCode.Usage,
                "keyward run --env NAME=<profile>:<key> [--env ...] [--all <profile> [--prefix P_]] -- <program> [arguments]");
        }

        var options = Options.Parse(args[..separator], values: ["--all", "--prefix"], repeatable: ["--env"]);
        var variables = new Dictionary<string, string>(StringComparer.Ordinal);

        if (options.Value("--all") is { } allProfile)
        {
            var prefix = options.Value("--prefix") ?? "";
            foreach (var (key, value) in await ReadAllAsync(allProfile))
            {
                variables[SecretReference.VariableNameFor(key, prefix)] = value ?? "";
            }
        }

        foreach (var assignment in options.Values("--env"))
        {
            var equals = assignment.IndexOf('=');
            if (equals <= 0)
            {
                throw new KeywardCliException(KeywardExitCode.Usage, $"'{assignment}' is no assignment - write NAME=<profile>:<key>.");
            }

            variables[assignment[..equals].Trim()] = await LookupAsync(SecretReference.Parse(assignment[(equals + 1)..]));
        }

        if (variables.Count == 0)
        {
            throw new KeywardCliException(KeywardExitCode.Usage, "Nothing to pass on - give at least one --env or --all.");
        }

        var program = args[separator + 1];
        var start = new ProcessStartInfo(ResolveProgram(program)) { UseShellExecute = false };
        foreach (var argument in args[(separator + 2)..])
        {
            start.ArgumentList.Add(argument);
        }

        foreach (var (name, value) in variables)
        {
            start.Environment[name] = value;
        }

        return (KeywardExitCode)await context.RunProcess(start);
    }

    private async Task<KeywardExitCode> HeadersAsync(string[] args)
    {
        var options = Options.Parse(args, repeatable: ["--set"]);
        var headers = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var setting in options.Values("--set"))
        {
            var equals = setting.IndexOf('=');
            if (equals <= 0)
            {
                throw new KeywardCliException(KeywardExitCode.Usage, $"'{setting}' is no header - write \"Name=text with {{profile:key}}\".");
            }

            headers[setting[..equals].Trim()] = await ExpandAsync(setting[(equals + 1)..]);
        }

        if (headers.Count == 0)
        {
            throw new KeywardCliException(KeywardExitCode.Usage, "keyward headers --set \"Authorization=Bearer {profile:key}\" [--set ...]");
        }

        // The JSON object Claude Code's headersHelper merges into the request headers.
        context.Out.WriteLine(JsonSerializer.Serialize(headers, Json));
        return KeywardExitCode.Ok;
    }

    private async Task<KeywardExitCode> EnvAsync(string[] args)
    {
        var options = Options.Parse(args, values: ["--shell", "--prefix"]);
        var profile = options.Positional(0, "keyward env <profile> [--shell powershell|sh] [--prefix P_]");
        var shell = options.Value("--shell") ?? (OperatingSystem.IsWindows() ? "powershell" : "sh");
        var prefix = options.Value("--prefix") ?? "";
        if (shell is not ("powershell" or "sh"))
        {
            throw new KeywardCliException(KeywardExitCode.Usage, "--shell is powershell or sh.");
        }

        foreach (var (key, value) in (await ReadAllAsync(profile)).OrderBy(p => p.Key, StringComparer.OrdinalIgnoreCase))
        {
            var name = SecretReference.VariableNameFor(key, prefix);
            var text = value ?? "";
            context.Out.WriteLine(shell == "powershell"
                ? $"$env:{name} = '{text.Replace("'", "''", StringComparison.Ordinal)}'"
                : $"export {name}='{text.Replace("'", "'\\''", StringComparison.Ordinal)}'");
        }

        context.Err.WriteLine("keyward: the values stay in this shell session until it ends - prefer 'keyward run' for a single program.");
        return KeywardExitCode.Ok;
    }

    // --- import (T30) ---

    private async Task<KeywardExitCode> ImportAsync(string[] args)
    {
        var options = Options.Parse(args, flags: ["--dry-run", "--overwrite"], values: ["--service", "--mapping", "--source"]);
        var service = options.Uri("--service");
        var mappingPath = options.Value("--mapping") ?? throw new KeywardCliException(KeywardExitCode.Usage, "--mapping <file.json> is required.");
        var sourcePath = options.Value("--source") ?? throw new KeywardCliException(KeywardExitCode.Usage, "--source <file> is required.");

        var plan = SecretImport.Plan(ReadFile(mappingPath), File.ReadAllLines(sourcePath));
        foreach (var problem in plan.Problems)
        {
            context.Err.WriteLine($"keyward: {problem}");
        }

        if (plan.Problems.Count > 0)
        {
            context.Err.WriteLine("keyward: nothing was written - fix the mapping first (keyward never guesses a value).");
            return KeywardExitCode.Usage;
        }

        if (options.Has("--dry-run"))
        {
            foreach (var row in plan.Rows)
            {
                context.Out.WriteLine($"line {row.Line}: {row.Application} / {row.Environment} / {row.Key}  ({row.Value.Length} characters)");
            }

            context.Err.WriteLine($"keyward: {plan.Rows.Count} value(s) would be written. Run again without --dry-run.");
            return KeywardExitCode.Ok;
        }

        var agentToken = context.AgentTokenFor(service) ?? throw new KeywardCliException(KeywardExitCode.NoProfile,
            $"No AI agent token stored for {service.GetLeftPart(UriPartial.Authority)}. Store one with 'amkeyward-mcp setup {service.GetLeftPart(UriPartial.Authority)}' (it needs 'Manage applications').");

        using var http = context.HttpClientFor(service, agentToken, ImportTimeout);
        var written = await SecretImport.WriteAsync(http, plan.Rows, options.Has("--overwrite"), context.Out);
        context.Err.WriteLine($"keyward: {written} value(s) written. Delete the plain-text file once every consumer reads from Keyward.");
        return KeywardExitCode.Ok;
    }

    // --- PowerShell vault (T21) ---

    private KeywardExitCode PowerShell(string[] args)
    {
        var options = Options.Parse(args, flags: ["--windows-powershell"], values: ["--path"]);
        if (options.Positional(0, "keyward powershell install [--windows-powershell] [--path <modules folder>]") != "install")
        {
            throw new KeywardCliException(KeywardExitCode.Usage, "keyward powershell install [--windows-powershell] [--path <modules folder>]");
        }

        var modules = options.Value("--path") ?? context.PowerShellModulesFolder(options.Has("--windows-powershell"));
        var target = PowerShellModule.Install(modules);
        context.Err.WriteLine($"PowerShell vault installed in {target}. Next:");
        context.Out.WriteLine("Install-Module Microsoft.PowerShell.SecretManagement -Scope CurrentUser");
        context.Out.WriteLine("Register-SecretVault -Name Keyward -ModuleName Am.Keyward.SecretManagement -VaultParameters @{ Profile = '<profile>' }");
        context.Out.WriteLine("Get-Secret -Vault Keyward -Name '<key>' -AsPlainText");
        return KeywardExitCode.Ok;
    }

    private KeywardExitCode Version()
    {
        var version = typeof(KeywardCli).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "?";
        context.Out.WriteLine($"keyward {version.Split('+')[0]}");
        return KeywardExitCode.Ok;
    }

    private KeywardExitCode Help()
    {
        context.Out.WriteLine("""
            keyward - read secrets from AM KEYWARD in scripts and tools (app token per profile)

              keyward login <profile> --service <url> [--token-stdin]   store an app token (Credential Manager / Keychain)
              keyward logout <profile>                                   forget it on this computer
              keyward profiles                                           list profiles (never values)
              keyward get <profile>:<key> [--json]                       print one value
              keyward keys <profile> [--json]                            list the keys the token can read
              keyward run --env NAME=<profile>:<key> [--all <profile> [--prefix P_]] -- <program> [arguments]
                                                                         start a program with values as environment variables
              keyward headers --set "Authorization=Bearer {<profile>:<key>}"
                                                                         JSON for Claude Code's headersHelper
              keyward env <profile> [--shell powershell|sh] [--prefix P_] assignments for this shell session
              keyward import --service <url> --mapping <map.json> --source <file> [--dry-run] [--overwrite]
                                                                         move a plain-text secrets file into Keyward
              keyward powershell install [--windows-powershell]          add the PowerShell SecretManagement vault

            Never wrap an AI agent itself (keyward run -- claude): its shell could print the values. Wrap a single MCP
            server, or use headersHelper. Exit codes: 0 ok, 2 usage, 3 no profile, 4 token rejected, 5 network not
            allowed, 6 unknown key, 7 no value in this environment, 8 unreachable, 1 other.
            """);
        return KeywardExitCode.Ok;
    }

    // --- helpers ---

    private async Task<string> LookupAsync(SecretReference reference)
    {
        var profile = context.Profiles.Find(reference.Profile);
        using var http = context.HttpClientFor(profile.ServiceUri, context.Profiles.TokenFor(profile), RequestTimeout);
        var lookup = await ClientFor(http, profile).LookupAsync(reference.Key);
        return lookup.Status switch
        {
            KeywardSecretLookupStatus.Found => lookup.Value ?? "",
            KeywardSecretLookupStatus.UnknownKey => throw new KeywardCliException(KeywardExitCode.UnknownKey,
                $"The application of profile '{profile.Name}' has no key '{reference.Key}'."),
            KeywardSecretLookupStatus.NoValue => throw new KeywardCliException(KeywardExitCode.NoValue,
                $"Key '{reference.Key}' has no value in the environment of profile '{profile.Name}'."),
            KeywardSecretLookupStatus.TokenRejected => throw TokenRejected(profile),
            _ => throw NetworkNotAllowed(profile),
        };
    }

    private async Task<IReadOnlyDictionary<string, string?>> ReadAllAsync(string profileName)
    {
        var profile = context.Profiles.Find(profileName);
        using var http = context.HttpClientFor(profile.ServiceUri, context.Profiles.TokenFor(profile), RequestTimeout);
        try
        {
            return await ClientFor(http, profile).GetAllAsync();
        }
        catch (HttpRequestException ex) when (ex.StatusCode == HttpStatusCode.Unauthorized)
        {
            throw TokenRejected(profile);
        }
        catch (HttpRequestException ex) when (ex.StatusCode == HttpStatusCode.Forbidden)
        {
            throw NetworkNotAllowed(profile);
        }
    }

    private async Task<string> ExpandAsync(string template)
    {
        var result = template;
        foreach (Match placeholder in Regex.Matches(template, @"\{([^{}]+)\}"))
        {
            result = result.Replace(placeholder.Value, await LookupAsync(SecretReference.Parse(placeholder.Groups[1].Value)), StringComparison.Ordinal);
        }

        return result;
    }

    // KeywardSecretsClient expects the API base as its base address.
    private static KeywardSecretsClient ClientFor(HttpClient http, KeywardProfile profile)
    {
        http.BaseAddress = new Uri(profile.ServiceUri, ClientPath(""));
        return new KeywardSecretsClient(http);
    }

    private static string ClientPath(string relative) => $"{KeywardApiDefaults.BasePath.TrimEnd('/')}/{relative}";

    private static void ThrowForAccess(HttpStatusCode status)
    {
        if (status == HttpStatusCode.Unauthorized)
        {
            throw new KeywardCliException(KeywardExitCode.TokenRejected, "Keyward rejected the token (unknown, revoked or expired). Nothing was stored.");
        }

        if (status == HttpStatusCode.Forbidden)
        {
            throw new KeywardCliException(KeywardExitCode.NetworkNotAllowed,
                "This computer's network may not use the software-client API (Keyward:Client:AllowedNetworks). Nothing was stored.");
        }
    }

    private static KeywardCliException TokenRejected(KeywardProfile profile) => new(KeywardExitCode.TokenRejected,
        $"Keyward rejected the app token of profile '{profile.Name}' (unknown, revoked or expired). Store a new one with: keyward login {profile.Name} --service {profile.ServiceUri.GetLeftPart(UriPartial.Authority)}");

    private static KeywardCliException NetworkNotAllowed(KeywardProfile profile) => new(KeywardExitCode.NetworkNotAllowed,
        $"This computer's network may not use the software-client API of {profile.ServiceUri.Host} (Keyward:Client:AllowedNetworks).");

    private static string ReadFile(string path) =>
        File.Exists(path) ? File.ReadAllText(path) : throw new KeywardCliException(KeywardExitCode.Usage, $"File not found: {path}");

    /// <summary>
    /// A program without a path or extension, as a person types it («node», «npx»): Windows finds only .exe on its own,
    /// so look it up along PATH with PATHEXT (.cmd, .bat …) the way a shell does. Elsewhere the OS resolves it.
    /// </summary>
    internal static string ResolveProgram(string program)
    {
        if (!OperatingSystem.IsWindows() || Path.IsPathRooted(program) || Path.HasExtension(program) || program.Contains(Path.DirectorySeparatorChar))
        {
            return program;
        }

        var extensions = (Environment.GetEnvironmentVariable("PATHEXT") ?? ".COM;.EXE;.BAT;.CMD").Split(';', StringSplitOptions.RemoveEmptyEntries);
        foreach (var folder in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            foreach (var extension in extensions)
            {
                var candidate = Path.Combine(folder.Trim(), program + extension);
                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }
        }

        return program;
    }

    /// <summary>The HTTP client the program uses: base address = installation root, Bearer token, timeout.</summary>
    public static HttpClient CreateHttpClient(Uri service, string token, TimeSpan timeout)
    {
        var http = new HttpClient { BaseAddress = new Uri(service.GetLeftPart(UriPartial.Authority) + "/"), Timeout = timeout };
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return http;
    }
}
