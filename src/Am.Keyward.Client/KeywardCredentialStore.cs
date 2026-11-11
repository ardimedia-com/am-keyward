using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

namespace Am.Keyward.Client;

/// <summary>
/// Where a Keyward token is kept on a workstation or server: the agent token of `amkeyward-mcp` and the app-token
/// profiles of `keyward`. Shared by both programs and the PowerShell vault, so there is one implementation per
/// operating system.
/// </summary>
public interface IKeywardCredentialStore
{
    /// <summary>The store's name for messages, e.g. «the Windows Credential Manager».</summary>
    string Place { get; }

    string? Read();

    void Write(string token);

    /// <summary>Forgets the stored token. False when there was none.</summary>
    bool Delete();
}

/// <summary>
/// The operating system's own secret store for the agent token: the Windows Credential Manager or the macOS Keychain.
/// Nothing is written to a file or an environment variable, and the MCP configuration of the assistant never contains
/// the token.
/// <para>
/// One entry per KEYWARD: the name carries the address the user configured (<see cref="AgentTarget"/>), so one computer
/// can hold tokens for any number of KEYWARD installations — none of them known when this tool was built — and a token
/// is only ever sent to the address it was stored for (<see cref="FindAgentToken"/>). <see cref="LegacyAgentTarget"/>,
/// the single entry of versions before 0.24, is never read as a token: <c>amkeyward-mcp setup &lt;address&gt;</c> moves
/// it to that address once.
/// </para>
/// </summary>
public static class KeywardCredentialStore
{
    /// <summary>
    /// The single agent-token entry of `amkeyward-mcp` before 0.24. Not bound to any address, so it is never used to
    /// call a KEYWARD; <c>setup &lt;address&gt;</c> moves it to that address's entry and deletes it.
    /// </summary>
    public const string LegacyAgentTarget = "AmKeyward:Agent";

    /// <summary>
    /// The environment variable holding an agent token where the computer has no credential store (Linux, a
    /// container). It is not bound to an address, so it is ignored wherever a credential store exists.
    /// </summary>
    public const string AgentTokenVariable = "KEYWARD_AGENT_TOKEN";

    /// <summary>
    /// The entry of an agent token for a KEYWARD address: <c>AmKeyward:Agent:{host[:port]}</c> for https, lower case.
    /// A plain-http address (accepted for loopback only) gets its own entry, <c>AmKeyward:Agent:http://{host:port}</c>,
    /// so a token stored for https is never sent over http to the same name.
    /// </summary>
    public static string AgentTarget(Uri serviceUri)
    {
        ArgumentNullException.ThrowIfNull(serviceUri);
        var authority = (serviceUri.IsDefaultPort ? serviceUri.Host : $"{serviceUri.Host}:{serviceUri.Port}").ToLowerInvariant();
        return serviceUri.Scheme == Uri.UriSchemeHttps
            ? $"{LegacyAgentTarget}:{authority}"
            : $"{LegacyAgentTarget}:{serviceUri.Scheme.ToLowerInvariant()}://{authority}";
    }

    /// <summary>The entry of an app-token profile of `keyward`: <c>AmKeyward:App:{profile}</c>, lower case.</summary>
    public static string AppProfileTarget(string profile) => $"AmKeyward:App:{profile.Trim().ToLowerInvariant()}";

    /// <summary>The store on this computer, or null where there is none (Linux: environment variables instead).</summary>
    public static IKeywardCredentialStore? For(string target) =>
        OperatingSystem.IsWindows() ? new WindowsCredentialStore(target)
        : OperatingSystem.IsMacOS() ? new MacKeychainStore(target)
        : null;

    /// <summary>The agent token for this computer's KEYWARD at <paramref name="serviceUri"/> (see the other overload).</summary>
    public static KeywardAgentTokenLookup FindAgentToken(Uri serviceUri) =>
        FindAgentToken(serviceUri, For, Environment.GetEnvironmentVariable);

    /// <summary>
    /// The agent token stored for exactly this address — never one stored for another address or by a version before
    /// 0.24. Rules: the address must be https (http only to localhost); where a credential store exists only its entry
    /// for this address counts and <see cref="AgentTokenVariable"/> is ignored; where none exists (Linux) the
    /// environment variable is used — which is not bound to an address.
    /// </summary>
    public static KeywardAgentTokenLookup FindAgentToken(
        Uri serviceUri, Func<string, IKeywardCredentialStore?> storeFor, Func<string, string?> environment)
    {
        ArgumentNullException.ThrowIfNull(serviceUri);
        ArgumentNullException.ThrowIfNull(storeFor);
        ArgumentNullException.ThrowIfNull(environment);

        var display = KeywardServiceAddress.Root(serviceUri).AbsoluteUri.TrimEnd('/');
        if (!KeywardServiceAddress.IsSecure(serviceUri))
        {
            return new(null, $"{display} is not https; an agent token is only sent over https (plain http to localhost only).");
        }

        var setup = $"amkeyward-mcp setup {display}";
        if (storeFor(AgentTarget(serviceUri)) is not { } store)
        {
            return environment(AgentTokenVariable) is { Length: > 0 } fromEnvironment
                ? new(fromEnvironment, null)
                : new(null, $"No agent token for {display}: there is no credential store on this computer, so set {AgentTokenVariable}.");
        }

        if (store.Read() is { Length: > 0 } stored)
        {
            return new(stored, null);
        }

        var problem = $"No agent token stored for {display} in {store.Place}. Run '{setup}'.";
        if (storeFor(LegacyAgentTarget)?.Read() is { Length: > 0 })
        {
            problem += $" A token stored by a version before 0.24 is not bound to an address and is no longer used; '{setup}' moves it to this address.";
        }

        if (environment(AgentTokenVariable) is { Length: > 0 })
        {
            problem += $" {AgentTokenVariable} is ignored on a computer with a credential store, because it is not bound to an address.";
        }

        return new(null, problem);
    }
}

/// <summary>The outcome of <see cref="KeywardCredentialStore.FindAgentToken(Uri)"/>: the token, or why there is none.</summary>
public sealed record KeywardAgentTokenLookup(string? Token, string? Problem);

/// <summary>A generic credential in the Windows Credential Manager, persisted for this user on this machine.</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsCredentialStore(string target) : IKeywardCredentialStore
{
    public string Place => "the Windows Credential Manager";

    public string Target => target;

    private const uint CredTypeGeneric = 1;
    private const uint CredPersistLocalMachine = 2;

    public string? Read()
    {
        if (!CredRead(target, CredTypeGeneric, 0, out var pointer))
        {
            return null;
        }

        try
        {
            var credential = Marshal.PtrToStructure<Credential>(pointer);
            if (credential.CredentialBlobSize == 0 || credential.CredentialBlob == IntPtr.Zero)
            {
                return null;
            }

            var bytes = new byte[credential.CredentialBlobSize];
            Marshal.Copy(credential.CredentialBlob, bytes, 0, bytes.Length);
            return Encoding.Unicode.GetString(bytes);
        }
        finally
        {
            CredFree(pointer);
        }
    }

    public void Write(string token)
    {
        var bytes = Encoding.Unicode.GetBytes(token);
        var blob = Marshal.AllocHGlobal(bytes.Length);
        try
        {
            Marshal.Copy(bytes, 0, blob, bytes.Length);
            var credential = new Credential
            {
                Type = CredTypeGeneric,
                TargetName = target,
                Comment = target.StartsWith("AmKeyward:App:", StringComparison.Ordinal) ? "AM KEYWARD app token (keyward)" : "AM KEYWARD agent token (amkeyward-mcp)",
                CredentialBlobSize = (uint)bytes.Length,
                CredentialBlob = blob,
                Persist = CredPersistLocalMachine,
                UserName = Environment.UserName,
            };

            if (!CredWrite(ref credential, 0))
            {
                throw new InvalidOperationException($"Could not store the token in the Windows Credential Manager (error {Marshal.GetLastWin32Error()}).");
            }
        }
        finally
        {
            CryptographicClear(blob, bytes.Length);
            Marshal.FreeHGlobal(blob);
            Array.Clear(bytes);
        }
    }

    public bool Delete() => CredDelete(target, CredTypeGeneric, 0);

    private static void CryptographicClear(IntPtr pointer, int length)
    {
        for (var i = 0; i < length; i++)
        {
            Marshal.WriteByte(pointer, i, 0);
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct Credential
    {
        public uint Flags;
        public uint Type;
        public string TargetName;
        public string? Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        public string? TargetAlias;
        public string? UserName;
    }

    [DllImport("advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredRead(string target, uint type, uint flags, out IntPtr credential);

    [DllImport("advapi32.dll", EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredWrite(ref Credential credential, uint flags);

    [DllImport("advapi32.dll", EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredDelete(string target, uint type, uint flags);

    [DllImport("advapi32.dll")]
    private static extern void CredFree(IntPtr buffer);
}
