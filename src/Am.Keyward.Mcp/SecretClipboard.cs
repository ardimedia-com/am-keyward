using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Am.Keyward.Mcp;

/// <summary>Where a revealed secret goes instead of the assistant's context.</summary>
internal interface ISecretClipboard
{
    /// <summary>Whether this machine has a clipboard the secret can go to.</summary>
    bool IsAvailable { get; }

    /// <summary>Puts the value on the clipboard and clears it after <paramref name="clearAfter"/> unless something else was copied since.</summary>
    void CopyAndClearLater(string value, TimeSpan clearAfter);
}

/// <summary>
/// The Windows clipboard, marked so the secret stays out of the clipboard history (Win+V) and cloud sync and is
/// ignored by clipboard monitors, and cleared again after a short time — but only if the user has not copied
/// anything else meanwhile.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class WindowsSecretClipboard : ISecretClipboard
{
    private const uint CfUnicodeText = 13;
    private const uint GmemMoveable = 0x0002;

    public bool IsAvailable => true;

    public void CopyAndClearLater(string value, TimeSpan clearAfter)
    {
        Open();
        try
        {
            if (!EmptyClipboard())
            {
                throw new InvalidOperationException("Could not empty the clipboard.");
            }

            SetText(value);

            // Documented opt-outs (Windows 10 1809+): no history, no cloud clipboard, skip clipboard monitors.
            SetDword(RegisterClipboardFormat("CanIncludeInClipboardHistory"), 0);
            SetDword(RegisterClipboardFormat("CanUploadToCloudClipboard"), 0);
            SetDword(RegisterClipboardFormat("ExcludeClipboardContentFromMonitorProcessing"), 0);
        }
        finally
        {
            CloseClipboard();
        }

        var sequence = GetClipboardSequenceNumber();
        _ = Task.Run(async () =>
        {
            await Task.Delay(clearAfter).ConfigureAwait(false);
            if (GetClipboardSequenceNumber() != sequence)
            {
                return; // the user copied something else; leave it alone
            }

            try
            {
                Open();
                try { EmptyClipboard(); }
                finally { CloseClipboard(); }
            }
            catch (InvalidOperationException)
            {
                // Clipboard busy — nothing more to do; the value was marked for no history/cloud anyway.
            }
        });
    }

    private static void Open()
    {
        // Another application may hold the clipboard for a moment.
        for (var attempt = 0; attempt < 20; attempt++)
        {
            if (OpenClipboard(IntPtr.Zero))
            {
                return;
            }

            Thread.Sleep(50);
        }

        throw new InvalidOperationException("The clipboard is in use by another application.");
    }

    private static void SetText(string value)
    {
        var bytes = (value.Length + 1) * 2;
        var handle = GlobalAlloc(GmemMoveable, (UIntPtr)bytes);
        var target = GlobalLock(handle);
        try
        {
            var chars = (value + '\0').ToCharArray();
            Marshal.Copy(chars, 0, target, chars.Length);
            Array.Clear(chars);
        }
        finally
        {
            GlobalUnlock(handle);
        }

        if (SetClipboardData(CfUnicodeText, handle) == IntPtr.Zero)
        {
            throw new InvalidOperationException("Could not put the value on the clipboard.");
        }
    }

    private static void SetDword(uint format, int value)
    {
        var handle = GlobalAlloc(GmemMoveable, (UIntPtr)sizeof(int));
        var target = GlobalLock(handle);
        Marshal.WriteInt32(target, value);
        GlobalUnlock(handle);
        SetClipboardData(format, handle);
    }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool OpenClipboard(IntPtr owner);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool CloseClipboard();

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool EmptyClipboard();

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr SetClipboardData(uint format, IntPtr memory);

    [DllImport("user32.dll", EntryPoint = "RegisterClipboardFormatW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint RegisterClipboardFormat(string format);

    [DllImport("user32.dll")]
    private static extern uint GetClipboardSequenceNumber();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GlobalAlloc(uint flags, UIntPtr bytes);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GlobalLock(IntPtr memory);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GlobalUnlock(IntPtr memory);
}

/// <summary>No clipboard (not Windows): revealing is refused rather than falling back to the assistant's context.</summary>
internal sealed class NoSecretClipboard : ISecretClipboard
{
    public bool IsAvailable => false;

    public void CopyAndClearLater(string value, TimeSpan clearAfter) =>
        throw new PlatformNotSupportedException("Revealing needs the Windows clipboard.");
}
