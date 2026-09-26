using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

namespace Am.Keyward.Mcp;

/// <summary>Where the agent token is kept on the workstation.</summary>
internal interface ITokenStore
{
    string? Read();

    void Write(string token);
}

/// <summary>
/// The agent token in the Windows Credential Manager (a generic credential, target <see cref="Target"/>,
/// persisted for this user on this machine). Nothing is written to a file or an environment variable, and the
/// MCP configuration of the assistant never contains the token.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class WindowsCredentialStore : ITokenStore
{
    public const string Target = "AmKeyward:Agent";

    private const uint CredTypeGeneric = 1;
    private const uint CredPersistLocalMachine = 2;

    public string? Read()
    {
        if (!CredRead(Target, CredTypeGeneric, 0, out var pointer))
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
                TargetName = Target,
                Comment = "AM KEYWARD agent token (amkeyward-mcp)",
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

    [DllImport("advapi32.dll")]
    private static extern void CredFree(IntPtr buffer);
}

/// <summary>Elsewhere, or as a fallback: the token from the <c>KEYWARD_AGENT_TOKEN</c> environment variable.</summary>
internal sealed class EnvironmentTokenStore : ITokenStore
{
    public const string Variable = "KEYWARD_AGENT_TOKEN";

    public string? Read() => Environment.GetEnvironmentVariable(Variable) is { Length: > 0 } token ? token : null;

    public void Write(string token) =>
        throw new PlatformNotSupportedException($"Set the {Variable} environment variable instead.");
}
