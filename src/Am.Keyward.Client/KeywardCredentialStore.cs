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
/// One entry per KEYWARD: the name carries the address the user configured (<see cref="TargetFor"/>), so one computer
/// can hold tokens for any number of KEYWARD installations — none of them known when this tool was built.
/// <see cref="LegacyAgentTarget"/> is the single Windows target of versions before 0.24 and is still read as a fallback.
/// </para>
/// </summary>
public static class KeywardCredentialStore
{
    /// <summary>The single agent-token entry of `amkeyward-mcp` before 0.24 — still read as a fallback.</summary>
    public const string LegacyAgentTarget = "AmKeyward:Agent";

    /// <summary>The entry of an agent token for a KEYWARD address: <c>AmKeyward:Agent:{host[:port]}</c>, lower case.</summary>
    public static string AgentTarget(Uri serviceUri) =>
        $"{LegacyAgentTarget}:{(serviceUri.IsDefaultPort ? serviceUri.Host : $"{serviceUri.Host}:{serviceUri.Port}").ToLowerInvariant()}";

    /// <summary>The entry of an app-token profile of `keyward`: <c>AmKeyward:App:{profile}</c>, lower case.</summary>
    public static string AppProfileTarget(string profile) => $"AmKeyward:App:{profile.Trim().ToLowerInvariant()}";

    /// <summary>The store on this computer, or null where there is none (Linux: environment variables instead).</summary>
    public static IKeywardCredentialStore? For(string target) =>
        OperatingSystem.IsWindows() ? new WindowsCredentialStore(target)
        : OperatingSystem.IsMacOS() ? new MacKeychainStore(target)
        : null;
}

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
