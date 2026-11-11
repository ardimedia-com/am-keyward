using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace Am.Keyward.Mcp;

/// <summary>Where a revealed secret goes instead of the assistant's context.</summary>
internal interface ISecretClipboard
{
    /// <summary>Whether this machine has a clipboard the secret can go to at all.</summary>
    bool IsAvailable { get; }

    /// <summary>
    /// Checks — without changing the clipboard — that it can be used right now. Null when it can; otherwise why not,
    /// in words for the assistant. Called before a one-time reveal is consumed, so a busy or missing clipboard does not
    /// burn the approval.
    /// </summary>
    string? Probe();

    /// <summary>Puts the value on the clipboard and clears it after <paramref name="clearAfter"/> unless something else was copied since.</summary>
    void CopyAndClearLater(string value, TimeSpan clearAfter);

    /// <summary>
    /// Runs a pending clear at once (same rule: only if the clipboard still holds the value). Called when the server
    /// stops, so a value never outlives the process that put it there.
    /// </summary>
    void ClearPendingNow();
}

/// <summary>
/// The shared part of a real clipboard: one pending clear at a time, run by a timer or — when the server stops first —
/// synchronously by <see cref="ClearPendingNow"/>, exactly once either way. Whether the clipboard still holds the value
/// is decided by comparing a SHA-256 fingerprint of its current text, so the value itself is not kept around, and
/// something the user copied meanwhile is never cleared.
/// </summary>
internal abstract class ClearingSecretClipboard : ISecretClipboard
{
    private readonly Lock gate = new();
    private PendingClear? pending;

    public bool IsAvailable => true;

    public abstract string? Probe();

    public void CopyAndClearLater(string value, TimeSpan clearAfter)
    {
        var entry = new PendingClear(Fingerprint(value));
        Copy(value);

        PendingClear? replaced;
        lock (gate)
        {
            replaced = pending;
            pending = entry;
        }

        // The earlier value was overwritten by this one; its clear has nothing left to do.
        replaced?.Cancel();
        entry.Timer = new Timer(_ => Run(entry), null, clearAfter, Timeout.InfiniteTimeSpan);
    }

    public void ClearPendingNow()
    {
        PendingClear? entry;
        lock (gate)
        {
            entry = pending;
        }

        if (entry is not null)
        {
            Run(entry);
        }
    }

    /// <summary>Puts the text on the clipboard; throws <see cref="InvalidOperationException"/> when it cannot.</summary>
    protected abstract void Copy(string value);

    /// <summary>Empties the clipboard if <paramref name="holdsTheValue"/> says its current text is still the value.</summary>
    protected abstract void ClearIf(Func<string?, bool> holdsTheValue);

    private void Run(PendingClear entry)
    {
        if (!entry.TryStart())
        {
            return;
        }

        lock (gate)
        {
            if (ReferenceEquals(pending, entry))
            {
                pending = null;
            }
        }

        try
        {
            ClearIf(text => text is not null && CryptographicOperations.FixedTimeEquals(Fingerprint(text), entry.Fingerprint));
        }
        catch (Exception ex) when (ex is InvalidOperationException or ExternalException or System.ComponentModel.Win32Exception)
        {
            // Clipboard busy or gone — nothing more to do; on Windows the value was kept out of history and cloud anyway.
        }
    }

    private static byte[] Fingerprint(string value) => SHA256.HashData(Encoding.UTF8.GetBytes(value));

    private sealed class PendingClear(byte[] fingerprint)
    {
        private int started;

        public byte[] Fingerprint { get; } = fingerprint;

        public Timer? Timer { get; set; }

        public bool TryStart()
        {
            if (Interlocked.Exchange(ref started, 1) != 0)
            {
                return false;
            }

            Timer?.Dispose();
            return true;
        }

        public void Cancel()
        {
            Interlocked.Exchange(ref started, 1);
            Timer?.Dispose();
        }
    }
}

/// <summary>
/// The Windows clipboard, marked so the secret stays out of the clipboard history (Win+V) and cloud sync and is
/// ignored by clipboard monitors, and cleared again after a short time — but only if it still holds the value.
/// The check compares the clipboard's current text while the clipboard is open, so a copy another program makes in
/// between is never cleared (a sequence number cannot tell: <c>CloseClipboard</c> itself advances it when Windows adds
/// the synthesized text formats).
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class WindowsSecretClipboard : ClearingSecretClipboard
{
    private const uint CfUnicodeText = 13;
    private const uint GmemMoveable = 0x0002;

    public override string? Probe()
    {
        try
        {
            Open();
            CloseClipboard();
            return null;
        }
        catch (InvalidOperationException ex)
        {
            return ex.Message;
        }
    }

    protected override void Copy(string value)
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
    }

    protected override void ClearIf(Func<string?, bool> holdsTheValue)
    {
        Open();
        try
        {
            if (holdsTheValue(ReadText()))
            {
                EmptyClipboard();
            }
        }
        finally
        {
            CloseClipboard();
        }
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

    private static string? ReadText()
    {
        var handle = GetClipboardData(CfUnicodeText);
        if (handle == IntPtr.Zero)
        {
            return null;
        }

        var source = GlobalLock(handle);
        if (source == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            return Marshal.PtrToStringUni(source);
        }
        finally
        {
            GlobalUnlock(handle);
        }
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
            GlobalFree(handle); // still ours: the clipboard did not take it
            throw new InvalidOperationException("Could not put the value on the clipboard.");
        }
    }

    private static void SetDword(uint format, int value)
    {
        var handle = GlobalAlloc(GmemMoveable, (UIntPtr)sizeof(int));
        var target = GlobalLock(handle);
        Marshal.WriteInt32(target, value);
        GlobalUnlock(handle);
        if (SetClipboardData(format, handle) == IntPtr.Zero)
        {
            GlobalFree(handle);
        }
    }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool OpenClipboard(IntPtr owner);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool CloseClipboard();

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool EmptyClipboard();

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr SetClipboardData(uint format, IntPtr memory);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr GetClipboardData(uint format);

    [DllImport("user32.dll", EntryPoint = "RegisterClipboardFormatW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint RegisterClipboardFormat(string format);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GlobalAlloc(uint flags, UIntPtr bytes);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GlobalLock(IntPtr memory);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GlobalUnlock(IntPtr memory);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GlobalFree(IntPtr memory);
}

/// <summary>
/// The macOS clipboard through <c>pbcopy</c> / <c>pbpaste</c>; the value goes through standard input, never a command
/// line. Cleared after a short time — but only if the clipboard still holds the value, so something the user copied
/// meanwhile stays.
/// <para>
/// Limitation: <c>pbcopy</c> cannot mark the value as concealed or transient (<c>org.nspasteboard.ConcealedType</c> /
/// <c>TransientType</c>), so a clipboard history — the one in Spotlight since macOS 26, or a third-party clipboard
/// manager — may record it until that history entry expires or is removed. Writing through NSPasteboard with those
/// markers needs Objective-C interop that is not done here.
/// </para>
/// </summary>
[SupportedOSPlatform("macos")]
internal sealed class MacSecretClipboard : ClearingSecretClipboard
{
    private const string CopyTool = "/usr/bin/pbcopy";
    private const string PasteTool = "/usr/bin/pbpaste";

    public override string? Probe()
    {
        if (!File.Exists(CopyTool) || !File.Exists(PasteTool))
        {
            return "pbcopy/pbpaste are missing on this Mac.";
        }

        try
        {
            // A read leaves the clipboard as it is and fails where there is no pasteboard (e.g. an SSH session).
            using var process = Start(PasteTool, redirectInput: false);
            process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            return process.ExitCode == 0 ? null : "The macOS clipboard is not reachable from this session.";
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return $"The macOS clipboard is not reachable: {ex.Message}";
        }
    }

    protected override void Copy(string value)
    {
        using var process = Start(CopyTool, redirectInput: true);
        process.StandardInput.Write(value);
        process.StandardInput.Close();
        process.WaitForExit();
        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException("Could not put the value on the clipboard.");
        }
    }

    protected override void ClearIf(Func<string?, bool> holdsTheValue)
    {
        using var process = Start(PasteTool, redirectInput: false);
        var text = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        if (holdsTheValue(text))
        {
            Copy("");
        }
    }

    private static System.Diagnostics.Process Start(string file, bool redirectInput) =>
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(file)
        {
            RedirectStandardInput = redirectInput,
            RedirectStandardOutput = !redirectInput,
            UseShellExecute = false,
        }) ?? throw new InvalidOperationException($"Could not start {file}.");
}

/// <summary>No clipboard (Linux, a server): revealing is refused rather than falling back to the assistant's context.</summary>
internal sealed class NoSecretClipboard : ISecretClipboard
{
    public bool IsAvailable => false;

    public string? Probe() => "Revealing needs the Windows or macOS clipboard, which is not available here.";

    public void CopyAndClearLater(string value, TimeSpan clearAfter) =>
        throw new PlatformNotSupportedException("Revealing needs the Windows or macOS clipboard.");

    public void ClearPendingNow()
    {
    }
}

internal static class SecretClipboard
{
    /// <summary>The clipboard of this computer, or none.</summary>
    public static ISecretClipboard ForThisComputer() =>
        OperatingSystem.IsWindows() ? new WindowsSecretClipboard()
        : OperatingSystem.IsMacOS() ? new MacSecretClipboard()
        : new NoSecretClipboard();
}
