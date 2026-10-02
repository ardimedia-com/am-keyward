using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

namespace Am.Keyward.Mcp;

/// <summary>
/// A generic password in the user's macOS login keychain (service = the entry name, account = the macOS user). The
/// Security framework is called directly, so the token never appears on a command line, where other processes could
/// read it (as it would with the <c>security</c> tool). The SecKeychain* calls are the long-standing generic-password
/// API — deprecated in favour of SecItem*, but still supported and far simpler to call without CoreFoundation glue.
/// </summary>
[SupportedOSPlatform("macos")]
internal sealed class MacKeychainStore(string service) : ITokenStore
{
    private const int ErrSecItemNotFound = -25300;
    private const int ErrSecDuplicateItem = -25299;

    public string Place => "the macOS Keychain";

    public string? Read()
    {
        var status = Find(out var length, out var data, out var item);
        if (status == ErrSecItemNotFound)
        {
            return null;
        }

        Check(status, "read");
        try
        {
            if (length == 0 || data == IntPtr.Zero)
            {
                return null;
            }

            var bytes = new byte[length];
            Marshal.Copy(data, bytes, 0, bytes.Length);
            var token = Encoding.UTF8.GetString(bytes);
            Array.Clear(bytes);
            return token;
        }
        finally
        {
            SecKeychainItemFreeContent(IntPtr.Zero, data);
            Release(item);
        }
    }

    public void Write(string token)
    {
        var password = Encoding.UTF8.GetBytes(token);
        var (serviceBytes, account) = Names();
        try
        {
            var status = SecKeychainAddGenericPassword(
                IntPtr.Zero, (uint)serviceBytes.Length, serviceBytes, (uint)account.Length, account, (uint)password.Length, password, out var added);
            if (status == ErrSecDuplicateItem)
            {
                // Already there (a new token for the same KEYWARD): replace the value in place.
                Check(Find(out _, out var oldData, out var item), "read");
                SecKeychainItemFreeContent(IntPtr.Zero, oldData);
                try
                {
                    Check(SecKeychainItemModifyAttributesAndData(item, IntPtr.Zero, (uint)password.Length, password), "update");
                }
                finally
                {
                    Release(item);
                }

                return;
            }

            Check(status, "store");
            Release(added);
        }
        finally
        {
            Array.Clear(password);
        }
    }

    public bool Delete()
    {
        var status = Find(out _, out var data, out var item);
        if (status == ErrSecItemNotFound)
        {
            return false;
        }

        Check(status, "read");
        SecKeychainItemFreeContent(IntPtr.Zero, data);
        try
        {
            Check(SecKeychainItemDelete(item), "delete");
            return true;
        }
        finally
        {
            Release(item);
        }
    }

    private int Find(out uint length, out IntPtr data, out IntPtr item)
    {
        var (serviceBytes, account) = Names();
        return SecKeychainFindGenericPassword(
            IntPtr.Zero, (uint)serviceBytes.Length, serviceBytes, (uint)account.Length, account, out length, out data, out item);
    }

    private (byte[] Service, byte[] Account) Names() =>
        (Encoding.UTF8.GetBytes(service), Encoding.UTF8.GetBytes(Environment.UserName));

    private static void Check(int status, string action)
    {
        if (status != 0)
        {
            throw new InvalidOperationException($"Could not {action} the token in the macOS Keychain (OSStatus {status}).");
        }
    }

    private static void Release(IntPtr item)
    {
        if (item != IntPtr.Zero)
        {
            CFRelease(item);
        }
    }

    private const string Security = "/System/Library/Frameworks/Security.framework/Security";
    private const string CoreFoundation = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";

    [DllImport(Security)]
    private static extern int SecKeychainFindGenericPassword(
        IntPtr keychainOrArray, uint serviceNameLength, byte[] serviceName, uint accountNameLength, byte[] accountName,
        out uint passwordLength, out IntPtr passwordData, out IntPtr itemRef);

    [DllImport(Security)]
    private static extern int SecKeychainAddGenericPassword(
        IntPtr keychain, uint serviceNameLength, byte[] serviceName, uint accountNameLength, byte[] accountName,
        uint passwordLength, byte[] passwordData, out IntPtr itemRef);

    [DllImport(Security)]
    private static extern int SecKeychainItemModifyAttributesAndData(IntPtr itemRef, IntPtr attrList, uint length, byte[] data);

    [DllImport(Security)]
    private static extern int SecKeychainItemDelete(IntPtr itemRef);

    [DllImport(Security)]
    private static extern int SecKeychainItemFreeContent(IntPtr attrList, IntPtr data);

    [DllImport(CoreFoundation)]
    private static extern void CFRelease(IntPtr cf);
}
