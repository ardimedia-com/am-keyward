using Am.Keyward.Client;
using System.Net.Http.Headers;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Am.Keyward.Mcp;

/// <summary>
/// Entry point. <c>amkeyward-mcp</c> runs the MCP server on stdio (what the assistant starts); <c>setup &lt;address&gt;</c>
/// stores the agent token for that KEYWARD in the Windows Credential Manager or the macOS Keychain; <c>check</c> verifies it;
/// <c>remove &lt;address&gt;</c> forgets the stored token again.
/// <para>
/// The KEYWARD address comes from the environment variable <c>Keyward__ServiceUri</c> ONLY. No configuration file is
/// read — not even an <c>appsettings.json</c> in the folder the assistant happens to run in, which a cloned repository
/// controls — and the token used is the one stored for exactly that address (see
/// <see cref="KeywardCredentialStore.FindAgentToken(Uri)"/>), so a project that registers this server with another
/// address gets no token to send there. Several KEYWARD installations on one computer are several MCP registrations,
/// each with its own address and its own stored token. An explicit class, not top-level statements, so it does not
/// collide with another <c>Program</c> where both are referenced (the test project).
/// </para>
/// </summary>
internal static class KeywardMcpHost
{
    /// <summary>The one variable the address is read from.</summary>
    public const string ServiceUriVariable = "Keyward__ServiceUri";

    public static async Task<int> Main(string[] args)
    {
        var command = args.FirstOrDefault()?.ToLowerInvariant();
        if (command == "setup")
        {
            return Setup(args.Skip(1).FirstOrDefault() ?? Environment.GetEnvironmentVariable(ServiceUriVariable),
                KeywardCredentialStore.For, KeywardTokenInput.ReadHidden, Console.Error);
        }

        if (command == "remove")
        {
            return Remove(args.Skip(1).FirstOrDefault() ?? Environment.GetEnvironmentVariable(ServiceUriVariable));
        }

        var start = ResolveStart(Environment.GetEnvironmentVariable, KeywardCredentialStore.For);
        if (start.Problem is not null)
        {
            Console.Error.WriteLine(start.Problem);
            return 1;
        }

        var baseAddress = start.Address!;
        var token = start.Token!;

        // No configuration sources at all (no appsettings.json, no command line, no environment provider): nothing the
        // current folder holds can change where the token goes.
        var builder = Host.CreateEmptyApplicationBuilder(new HostApplicationBuilderSettings
        {
            ApplicationName = "amkeyward-mcp",
            ContentRootPath = AppContext.BaseDirectory,
        });

        // stdout belongs to the MCP protocol; every log line goes to stderr.
        builder.Logging.AddConsole(o => o.LogToStandardErrorThreshold = LogLevel.Trace);
        builder.Logging.SetMinimumLevel(LogLevel.Information);
        builder.Logging.AddFilter("System.Net.Http.HttpClient", LogLevel.Warning);

        builder.Services.AddHttpClient<KeywardAgentClient>(client =>
        {
            client.BaseAddress = KeywardServiceAddress.Root(baseAddress);
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.Timeout = KeywardAgentClient.Timeout;
        });

        var clipboard = SecretClipboard.ForThisComputer();
        builder.Services.AddSingleton(clipboard);

        if (command == "check")
        {
            using var checkHost = builder.Build();
            var client = checkHost.Services.GetRequiredService<KeywardAgentClient>();
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

        using var host = builder.Build();

        // A revealed value must not outlive the server: when the assistant ends the session (stdin closes), on Ctrl+C
        // or on any other orderly exit, a pending clear runs at once instead of being dropped with the process.
        host.Services.GetRequiredService<IHostApplicationLifetime>().ApplicationStopping.Register(clipboard.ClearPendingNow);
        AppDomain.CurrentDomain.ProcessExit += (_, _) => clipboard.ClearPendingNow();
        try
        {
            await host.RunAsync();
        }
        finally
        {
            clipboard.ClearPendingNow();
        }

        return 0;
    }

    /// <summary>What the server starts with: the address from <see cref="ServiceUriVariable"/> and the token stored for it.</summary>
    internal sealed record StartSettings(Uri? Address, string? Token, string? Problem);

    internal static StartSettings ResolveStart(Func<string, string?> environment, Func<string, IKeywardCredentialStore?> storeFor)
    {
        var configured = environment(ServiceUriVariable);
        if (string.IsNullOrWhiteSpace(configured))
        {
            return new(null, null, $"Set {ServiceUriVariable} to the KEYWARD address, e.g. https://keyward.example.com");
        }

        if (!KeywardServiceAddress.TryParse(configured, out var address, out var error))
        {
            return new(null, null, $"{ServiceUriVariable}: {error}");
        }

        var lookup = KeywardCredentialStore.FindAgentToken(address!, storeFor, environment);
        return lookup.Token is null ? new(address, null, lookup.Problem) : new(address, lookup.Token, null);
    }

    internal static int Setup(string? serviceUri, Func<string, IKeywardCredentialStore?> storeFor, Func<string> readHiddenToken, TextWriter err)
    {
        if (string.IsNullOrWhiteSpace(serviceUri))
        {
            err.WriteLine("Which KEYWARD is the token for? Run 'amkeyward-mcp setup https://keyward.example.com' with its address.");
            return 1;
        }

        if (!KeywardServiceAddress.TryParse(serviceUri, out var address, out var error))
        {
            err.WriteLine(error);
            return 1;
        }

        var target = KeywardCredentialStore.AgentTarget(address!);
        var authority = address!.GetLeftPart(UriPartial.Authority);
        if (storeFor(target) is not { } store)
        {
            err.WriteLine($"There is no credential store here (Windows or macOS); set {KeywardCredentialStore.AgentTokenVariable} instead. "
                + "Note that this variable is not bound to an address: every registration of amkeyward-mcp sends it to its own address.");
            return 1;
        }

        // The single entry of versions before 0.24 is no longer read: the address named here is the one it belongs to,
        // so it moves to that address's entry once and is deleted.
        if (storeFor(KeywardCredentialStore.LegacyAgentTarget) is { } legacy && legacy.Read() is { Length: > 0 } legacyToken)
        {
            if (store.Read() is not { Length: > 0 } && legacyToken.StartsWith("amkwa_", StringComparison.Ordinal))
            {
                store.Write(legacyToken);
                legacy.Delete();
                err.WriteLine($"Moved the token stored by a version before 0.24 to «{target}»: it is now used for {authority} only. "
                    + "Run 'amkeyward-mcp check' to verify it, or run setup again to paste a different token.");
                return 0;
            }

            legacy.Delete();
            err.WriteLine($"Deleted the token stored by a version before 0.24 («{KeywardCredentialStore.LegacyAgentTarget}»); it was no longer used.");
        }

        err.Write("Paste the agent token (shown as *) and press Enter: ");
        var token = readHiddenToken();
        err.WriteLine();
        if (!token.StartsWith("amkwa_", StringComparison.Ordinal))
        {
            err.WriteLine("That is not an agent token (it starts with amkwa_). Nothing was stored.");
            return 1;
        }

        // Confirms what arrived without showing the secret: the public prefix (the middle segment) and the length.
        err.WriteLine($"Received {KeywardTokenInput.Mask(token)} ({token.Length} characters).");

        store.Write(token);
        err.WriteLine($"Stored in {store.Place} as «{target}» (for {authority}). Run 'amkeyward-mcp check' to verify it.");
        return 0;
    }

    // Forgets the token stored for this KEYWARD, and the single token of versions before 0.24 if it is still there. The
    // token itself stays valid until it is revoked on «AI agent tokens».
    private static int Remove(string? serviceUri)
    {
        if (string.IsNullOrWhiteSpace(serviceUri) || !Uri.TryCreate(serviceUri, UriKind.Absolute, out var address))
        {
            Console.Error.WriteLine("Which KEYWARD? Run 'amkeyward-mcp remove https://keyward.example.com' with its address.");
            return 1;
        }

        if (KeywardCredentialStore.For(KeywardCredentialStore.AgentTarget(address)) is not { } store)
        {
            Console.Error.WriteLine($"Nothing is stored here; unset {KeywardCredentialStore.AgentTokenVariable} instead.");
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
