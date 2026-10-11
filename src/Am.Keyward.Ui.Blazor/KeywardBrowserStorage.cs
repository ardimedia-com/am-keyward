using Microsoft.JSInterop;

namespace Am.Keyward.Ui.Blazor;

/// <summary>
/// Circuit-scoped access to the small on/off UI preferences the embedded Keyward UI keeps in the browser's
/// localStorage (the open/closed state of a <see cref="KeywardArea"/>). One JS module import per circuit,
/// shared by every component that remembers something, instead of one import per component instance.
/// </summary>
/// <remarks>
/// Best-effort by contract: storage can be unavailable (private mode, blocked site data) and JS interop can
/// be (prerendering, a circuit tearing down). Every call then answers "nothing stored" or does nothing — a lost
/// preference is never worth breaking a page over. Registered by <c>AddKeywardUi</c>.
/// </remarks>
internal sealed class KeywardBrowserStorage(IJSRuntime js) : IAsyncDisposable
{
    private const string ModulePath = "./_content/Am.Keyward.Ui.Blazor/KeywardUi.razor.js";

    private Task<IJSObjectReference>? module;

    /// <summary>
    /// Reads a stored on/off preference: <c>true</c> / <c>false</c> when one is stored, <c>null</c> when nothing
    /// is stored or storage is unreachable — so the caller's own default stands.
    /// </summary>
    public async Task<bool?> ReadStateAsync(string key)
    {
        try
        {
            return await (await ModuleAsync()).InvokeAsync<bool?>("readState", key);
        }
        catch
        {
            ForgetFailedModule();
            return null;
        }
    }

    /// <summary>Stores an on/off preference. Failure is swallowed: the preference then lasts for this session only.</summary>
    public async Task WriteFlagAsync(string key, bool value)
    {
        try
        {
            await (await ModuleAsync()).InvokeVoidAsync("writeFlag", key, value);
        }
        catch
        {
            ForgetFailedModule();
        }
    }

    // Shared by concurrent callers (several areas read their state in the same first render).
    private Task<IJSObjectReference> ModuleAsync() =>
        module ??= js.InvokeAsync<IJSObjectReference>("import", ModulePath).AsTask();

    // A failed import (e.g. attempted while JS was not yet available) must not be cached for the whole circuit.
    private void ForgetFailedModule()
    {
        if (module is { IsFaulted: true } or { IsCanceled: true })
        {
            module = null;
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (module is { IsCompletedSuccessfully: true })
        {
            try
            {
                await module.Result.DisposeAsync();
            }
            catch (JSDisconnectedException)
            {
                // Circuit already gone — nothing to release.
            }
        }
    }
}
