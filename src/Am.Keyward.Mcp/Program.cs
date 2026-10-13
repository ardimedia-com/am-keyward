using Am.Keyward.Client;
using System.Net.Http.Headers;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Am.Keyward.Mcp;

/// <summary>
/// Entry point. <c>amkeyward-mcp</c> runs the MCP server on stdio (what the assistant starts); <c>setup &lt;address&gt;</c>
/// stores the agent token for that KEYWARD in the Windows Credential Manager or the macOS Keychain; <c>check</c> verifies it;
/// <c>remove &lt;address&gt;</c> forgets the stored token again. The KEYWARD
/// address comes from configuration: the environment variable <c>Keyward__ServiceUri</c> (the same
/// <c>Keyward:ServiceUri</c> setting the other Keyward clients use). Several KEYWARD installations on one computer
/// are several MCP registrations, each with its own address and its own stored token. An explicit class, not
/// top-level statements, so it does not collide with another <c>Program</c> where both are referenced (the test project).
/// </summary>
internal static class KeywardMcpHost
{
    public static async Task<int> Main(string[] args)
    {
        var command = args.FirstOrDefault()?.ToLowerInvariant();
        if (command == "setup")
        {
            return Setup(args.Skip(1).FirstOrDefault() ?? Environment.GetEnvironmentVariable("Keyward__ServiceUri"));
        }

        if (command == "remove")
        {
            return Remove(args.Skip(1).FirstOrDefault() ?? Environment.GetEnvironmentVariable("Keyward__ServiceUri"));
        }

        var builder = Host.CreateApplicationBuilder(args.Where(a => a != "check").ToArray());

        // stdout belongs to the MCP protocol; every log line goes to stderr.
        builder.Logging.AddConsole(o => o.LogToStandardErrorThreshold = LogLevel.Trace);
        builder.Logging.AddFilter("System.Net.Http.HttpClient", LogLevel.Warning);

        var serviceUri = builder.Configuration["Keyward:ServiceUri"];
        if (string.IsNullOrWhiteSpace(serviceUri) || !Uri.TryCreate(serviceUri, UriKind.Absolute, out var baseAddress))
        {
            Console.Error.WriteLine("Set Keyward__ServiceUri to the KEYWARD address, e.g. https://keyward.example.com");
            return 1;
        }

        var token = ReadToken(baseAddress);
        if (token is null)
        {
            Console.Error.WriteLine(
                $"No agent token found for {baseAddress}. Run 'amkeyward-mcp setup {baseAddress.GetLeftPart(UriPartial.Authority)}' or set {EnvironmentTokenStore.Variable}.");
            return 1;
        }

        builder.Services.AddHttpClient<KeywardAgentClient>(client =>
        {
            client.BaseAddress = baseAddress;
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.Timeout = TimeSpan.FromSeconds(30);
        });

        builder.Services.AddSingleton(_ => SecretClipboard.ForThisComputer());

        if (command == "check")
        {
            using var host = builder.Build();
            var client = host.Services.GetRequiredService<KeywardAgentClient>();
            var ping = await client.PingAsync(CancellationToken.None);
            if (!ping.Ok)
            {
                Console.Error.WriteLine(ping.Error);
                return 1;
            }

            Console.Error.WriteLine($"OK — the agent token works against {baseAddress}.");
            var info = await client.TokenInfoAsync(CancellationToken.None);
            Console.Error.WriteLine(info.Ok
                ? CheckReport.Describe(info.Value!)
                : $"(Permissions not shown: {info.Error} — the KEYWARD host may run an older version.)");
            return 0;
        }

        builder.Services
            .AddMcpServer()
            .WithStdioServerTransport()
            .WithTools<KeywardTools>();

        await builder.Build().RunAsync();
        return 0;
    }

    // The token stored for this KEYWARD, else the single token of versions before 0.24, else the environment variable.
    private static string? ReadToken(Uri serviceUri) =>
        KeywardCredentialStore.For(KeywardCredentialStore.AgentTarget(serviceUri))?.Read() is { Length: > 0 } stored ? stored
        : KeywardCredentialStore.For(KeywardCredentialStore.LegacyAgentTarget)?.Read() is { Length: > 0 } legacy ? legacy
        : new EnvironmentTokenStore().Read();

    private static int Setup(string? serviceUri)
    {
        if (string.IsNullOrWhiteSpace(serviceUri) || !Uri.TryCreate(serviceUri, UriKind.Absolute, out var address))
        {
            Console.Error.WriteLine("Which KEYWARD is the token for? Run 'amkeyward-mcp setup https://keyward.example.com' with its address.");
            return 1;
        }

        if (KeywardCredentialStore.For(KeywardCredentialStore.AgentTarget(address)) is not { } store)
        {
            Console.Error.WriteLine($"There is no credential store here (Windows or macOS); set {EnvironmentTokenStore.Variable} instead.");
            return 1;
        }

        Console.Error.Write("Paste the agent token (shown as *) and press Enter: ");
        var token = KeywardTokenInput.ReadHidden();
        Console.Error.WriteLine();
        if (!token.StartsWith("amkwa_", StringComparison.Ordinal))
        {
            Console.Error.WriteLine("That is not an agent token (it starts with amkwa_). Nothing was stored.");
            return 1;
        }

        // Confirms what arrived without showing the secret: the public prefix (the middle segment) and the length.
        Console.Error.WriteLine($"Received {KeywardTokenInput.Mask(token)} ({token.Length} characters).");

        store.Write(token);
        Console.Error.WriteLine($"Stored in {store.Place} as «{KeywardCredentialStore.AgentTarget(address)}» (for {address.GetLeftPart(UriPartial.Authority)}). Run 'amkeyward-mcp check' to verify it.");
        return 0;
    }

    // Forgets the token stored for this KEYWARD, and the single token of versions before 0.24, which every address
    // falls back to — otherwise the server would keep working with it. The token itself stays valid until it is
    // revoked on «AI agent tokens».
    private static int Remove(string? serviceUri)
    {
        if (string.IsNullOrWhiteSpace(serviceUri) || !Uri.TryCreate(serviceUri, UriKind.Absolute, out var address))
        {
            Console.Error.WriteLine("Which KEYWARD? Run 'amkeyward-mcp remove https://keyward.example.com' with its address.");
            return 1;
        }

        if (KeywardCredentialStore.For(KeywardCredentialStore.AgentTarget(address)) is not { } store)
        {
            Console.Error.WriteLine($"Nothing is stored here; unset {EnvironmentTokenStore.Variable} instead.");
            return 1;
        }

        var removed = store.Delete();
        var legacyRemoved = KeywardCredentialStore.For(KeywardCredentialStore.LegacyAgentTarget)!.Delete();
        Console.Error.WriteLine(removed || legacyRemoved
            ? $"Removed the stored token for {address.GetLeftPart(UriPartial.Authority)} from {store.Place}. Revoke it on «AI agent tokens» so it stops working everywhere."
            : $"No token was stored for {address.GetLeftPart(UriPartial.Authority)} on this computer.");
        return 0;
    }
}
