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
    private const string ModulePath = "./_content/Am.Keyward.Ui.Blazor/keyward-clipboard.js";

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

    /// <summary>
    /// Copies a secret (password, value, token) and clears the clipboard again after 30 seconds — but only when it still
    /// holds that secret, so something the user copied in the meantime survives. Reading the clipboard needs the
    /// browser's permission; where it is not already granted the clear is skipped silently rather than prompting.
    /// False when the copy itself was refused or the circuit is gone.
    /// </summary>
    public static async Task<bool> TryCopySecretToClipboardAsync(this IJSRuntime js, string text)
    {
        ArgumentNullException.ThrowIfNull(js);
        try
        {
            var module = await js.InvokeAsync<IJSObjectReference>("import", ModulePath);
            try
            {
                return await module.InvokeAsync<bool>("copySecret", text, (int)SecretExposure.ClipboardKept.TotalMilliseconds);
            }
            finally
            {
                await module.DisposeAsync();
            }
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
