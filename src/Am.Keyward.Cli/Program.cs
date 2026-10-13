using System.Diagnostics;
using Am.Keyward.Client;

namespace Am.Keyward.Cli;

/// <summary>Entry point of `keyward`. An explicit class (not top-level statements), like amkeyward-mcp.</summary>
internal static class KeywardCliHost
{
    public static Task<int> Main(string[] args)
    {
        var context = new KeywardCliContext
        {
            Out = Console.Out,
            Err = Console.Error,
            In = Console.In,
            Profiles = KeywardProfiles.ForThisUser(),
            HttpClientFor = KeywardCli.CreateHttpClient,
            ReadHiddenToken = KeywardTokenInput.ReadHidden,
            InputRedirected = Console.IsInputRedirected,
            AgentTokenFor = AgentToken,
            RunProcess = RunAsync,
            PowerShellModulesFolder = PowerShellModule.DefaultModulesFolder,
        };

        return new KeywardCli(context).RunAsync(args);
    }

    // The agent token `amkeyward-mcp setup` stored for this installation (for `keyward import`).
    private static string? AgentToken(Uri service) =>
        KeywardCredentialStore.For(KeywardCredentialStore.AgentTarget(service))?.Read() is { Length: > 0 } stored ? stored
        : Environment.GetEnvironmentVariable("KEYWARD_AGENT_TOKEN") is { Length: > 0 } fromEnvironment ? fromEnvironment
        : null;

    // The child shares this console: Ctrl+C reaches it directly, so keyward itself waits instead of dying first.
    private static async Task<int> RunAsync(ProcessStartInfo start)
    {
        ConsoleCancelEventHandler keepWaiting = (_, e) => e.Cancel = true;
        Console.CancelKeyPress += keepWaiting;
        try
        {
            using var process = Process.Start(start)
                ?? throw new KeywardCliException(KeywardExitCode.Failed, $"Could not start {start.FileName}.");
            await process.WaitForExitAsync();
            return process.ExitCode;
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            throw new KeywardCliException(KeywardExitCode.Failed, $"Could not start {start.FileName}: {ex.Message}");
        }
        finally
        {
            Console.CancelKeyPress -= keepWaiting;
        }
    }
}
