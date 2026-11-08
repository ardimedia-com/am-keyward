using Microsoft.JSInterop;

namespace Am.Keyward.Ui.Blazor;

/// <summary>
/// Copying to the clipboard, best-effort. The browser refuses <c>navigator.clipboard.writeText</c> when the document
/// is not focused (the user clicked and moved to another window before the call arrived) or when permission is
/// denied; that refusal is not a fault of the page and must not replace it with the error panel (bvd.li.toolbox
/// 28.10.2026, /amkeyward/vaults). The caller shows its «copied» check only when the copy really happened.
/// </summary>
public static class ClipboardInterop
{
    /// <summary>Copies <paramref name="text"/>; false when the browser refused or the circuit is gone.</summary>
    public static async Task<bool> TryCopyToClipboardAsync(this IJSRuntime js, string text)
    {
        ArgumentNullException.ThrowIfNull(js);
        try
        {
            await js.InvokeVoidAsync("navigator.clipboard.writeText", text);
            return true;
        }
        catch (JSException)
        {
            return false;
        }
        catch (JSDisconnectedException)
        {
            return false;
        }
    }
}
