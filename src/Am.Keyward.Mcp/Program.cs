using System.Net.Http.Headers;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Am.Keyward.Mcp;

/// <summary>
/// Entry point. <c>amkeyward-mcp</c> runs the MCP server on stdio (what the assistant starts); <c>setup</c> stores
/// the agent token in the Windows Credential Manager; <c>check</c> verifies it against KEYWARD. The KEYWARD address
/// comes from configuration: the environment variable <c>Keyward__ServiceUri</c> (the same <c>Keyward:ServiceUri</c>
/// setting the other Keyward clients use). An explicit class, not top-level statements, so it does not collide with
/// another <c>Program</c> where both are referenced (the test project).
/// </summary>
internal static class KeywardMcpHost
{
    public static async Task<int> Main(string[] args)
    {
        var command = args.FirstOrDefault()?.ToLowerInvariant();
        if (command == "setup")
        {
            return Setup();
        }

        var builder = Host.CreateApplicationBuilder(args.Where(a => a != "check").ToArray());

        // stdout belongs to the MCP protocol; every log line goes to stderr.
        builder.Logging.AddConsole(o => o.LogToStandardErrorThreshold = LogLevel.Trace);
        builder.Logging.AddFilter("System.Net.Http.HttpClient", LogLevel.Warning);

        var serviceUri = builder.Configuration["Keyward:ServiceUri"];
        var token = ReadToken();
        if (string.IsNullOrWhiteSpace(serviceUri) || !Uri.TryCreate(serviceUri, UriKind.Absolute, out var baseAddress))
        {
            Console.Error.WriteLine("Set Keyward__ServiceUri to the KEYWARD address, e.g. https://toolbox.bvd.li");
            return 1;
        }

        if (token is null)
        {
            Console.Error.WriteLine($"No agent token found. Run 'amkeyward-mcp setup' (Windows Credential Manager) or set {EnvironmentTokenStore.Variable}.");
            return 1;
        }

        builder.Services.AddHttpClient<KeywardAgentClient>(client =>
        {
            client.BaseAddress = baseAddress;
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.Timeout = TimeSpan.FromSeconds(30);
        });

        builder.Services.AddSingleton<ISecretClipboard>(_ =>
            OperatingSystem.IsWindows() ? new WindowsSecretClipboard() : new NoSecretClipboard());

        if (command == "check")
        {
            using var host = builder.Build();
            var ping = await host.Services.GetRequiredService<KeywardAgentClient>().PingAsync(CancellationToken.None);
            Console.Error.WriteLine(ping.Ok ? $"OK — the agent token works against {baseAddress}." : ping.Error);
            return ping.Ok ? 0 : 1;
        }

        builder.Services
            .AddMcpServer()
            .WithStdioServerTransport()
            .WithTools<KeywardTools>();

        await builder.Build().RunAsync();
        return 0;
    }

    private static string? ReadToken()
    {
        if (OperatingSystem.IsWindows() && new WindowsCredentialStore().Read() is { Length: > 0 } stored)
        {
            return stored;
        }

        return new EnvironmentTokenStore().Read();
    }

    private static int Setup()
    {
        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine($"The Windows Credential Manager is not available here; set {EnvironmentTokenStore.Variable} instead.");
            return 1;
        }

        Console.Error.Write("Paste the agent token (input is hidden) and press Enter: ");
        var token = ReadHidden();
        Console.Error.WriteLine();
        if (!token.StartsWith("amkwa_", StringComparison.Ordinal))
        {
            Console.Error.WriteLine("That is not an agent token (it starts with amkwa_). Nothing was stored.");
            return 1;
        }

        new WindowsCredentialStore().Write(token);
        Console.Error.WriteLine($"Stored in the Windows Credential Manager as «{WindowsCredentialStore.Target}». Run 'amkeyward-mcp check' to verify it.");
        return 0;
    }

    private static string ReadHidden()
    {
        var chars = new List<char>();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter) break;
            if (key.Key == ConsoleKey.Backspace) { if (chars.Count > 0) chars.RemoveAt(chars.Count - 1); continue; }
            if (!char.IsControl(key.KeyChar)) chars.Add(key.KeyChar);
        }

        return new string([.. chars]).Trim();
    }
}
