namespace Am.Keyward.Ui.Blazor;

/// <summary>Kind of a transient notification — drives styling and dismiss timing.</summary>
public enum KeywardNotifyKind
{
    Success,
    Error,
    Info,
}

/// <summary>
/// Port for the embedded Keyward UI's transient notifications ("Vault created", "Moved", an error, …). Keyward
/// pages depend on THIS, never on a concrete toast — so the library stays self-contained and framework-agnostic.
/// <para>
/// Standalone, the built-in <see cref="DefaultKeywardNotifier"/> renders these through Keyward's own
/// <c>KeywardToastHost</c> (a BlazorBlueprint-styled toast; see the UI design principle in the README). A host
/// that already has a toast system — e.g. a BlazorBlueprint app — SHOULD override this with an implementation
/// that routes onto its own toasts (BbToast), so the notifications are indistinguishable from the rest of the
/// app. Registered with <c>TryAdd</c> in <c>AddKeywardUi</c>, so a host override simply wins.
/// </para>
/// </summary>
public interface IKeywardNotifier
{
    /// <summary>A brief, positive confirmation — should be transient (auto-dismiss).</summary>
    void Success(string message);

    /// <summary>A failure the user must see — should persist longer / until dismissed.</summary>
    void Error(string message);

    /// <summary>Neutral information.</summary>
    void Info(string message);
}

/// <summary>One live toast in the built-in host.</summary>
public sealed record KeywardToast(Guid Id, string Message, KeywardNotifyKind Kind);

/// <summary>
/// Circuit-scoped store of the toasts the built-in <c>KeywardToastHost</c> shows. When a host overrides
/// <see cref="IKeywardNotifier"/> to use its own toasts, nothing writes here and it simply stays empty.
/// </summary>
public sealed class KeywardToastState
{
    private readonly List<KeywardToast> _toasts = [];

    public IReadOnlyList<KeywardToast> Toasts => _toasts;

    /// <summary>Raised on add/remove so the host component can re-render.</summary>
    public event Action? Changed;

    public KeywardToast Add(string message, KeywardNotifyKind kind)
    {
        KeywardToast toast = new(Guid.NewGuid(), message, kind);
        _toasts.Add(toast);
        Changed?.Invoke();
        return toast;
    }

    public void Remove(Guid id)
    {
        if (_toasts.RemoveAll(t => t.Id == id) > 0)
        {
            Changed?.Invoke();
        }
    }
}

/// <summary>
/// Default <see cref="IKeywardNotifier"/>: pushes onto <see cref="KeywardToastState"/>, which the built-in
/// <c>KeywardToastHost</c> renders as BlazorBlueprint-styled, auto-dismissing toasts. Used standalone; a
/// BlazorBlueprint host overrides <see cref="IKeywardNotifier"/> to use <c>BbToast</c> instead.
/// </summary>
public sealed class DefaultKeywardNotifier(KeywardToastState state) : IKeywardNotifier
{
    public void Success(string message) => state.Add(message, KeywardNotifyKind.Success);

    public void Error(string message) => state.Add(message, KeywardNotifyKind.Error);

    public void Info(string message) => state.Add(message, KeywardNotifyKind.Info);
}
