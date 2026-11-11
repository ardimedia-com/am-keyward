namespace Am.Keyward.Ui.Blazor;

/// <summary>How long a secret stays exposed in the page or on the clipboard before it is taken away again.</summary>
internal static class SecretExposure
{
    /// <summary>A revealed password, value or key is masked again after this time.</summary>
    public static readonly TimeSpan RevealVisible = TimeSpan.FromSeconds(30);

    /// <summary>A freshly issued token (shown once) leaves the page after this time.</summary>
    public static readonly TimeSpan IssuedTokenVisible = TimeSpan.FromMinutes(5);

    /// <summary>A copied secret is cleared from the clipboard after this time (when it is still there).</summary>
    public static readonly TimeSpan ClipboardKept = TimeSpan.FromSeconds(30);
}

/// <summary>
/// Runs one action after a delay unless it is cancelled or scheduled anew — re-hiding a revealed secret, dropping an
/// issued token. The component disposes it, which cancels a pending run. The action is expected to marshal onto the
/// renderer itself (<c>InvokeAsync</c>).
/// </summary>
internal sealed class DelayedAction : IDisposable
{
    private CancellationTokenSource? cts;

    /// <summary>Replaces any pending run with <paramref name="action"/> after <paramref name="delay"/>.</summary>
    public void Schedule(TimeSpan delay, Func<Task> action)
    {
        ArgumentNullException.ThrowIfNull(action);
        Cancel();
        var source = cts = new CancellationTokenSource();
        _ = RunAsync(delay, action, source.Token);
    }

    /// <summary>Drops a pending run.</summary>
    public void Cancel()
    {
        var source = cts;
        cts = null;
        if (source is not null)
        {
            source.Cancel();
            source.Dispose();
        }
    }

    public void Dispose() => Cancel();

    private static async Task RunAsync(TimeSpan delay, Func<Task> action, CancellationToken cancellationToken)
    {
        try
        {
            await Task.Delay(delay, cancellationToken);
            await action();
        }
        catch (OperationCanceledException)
        {
            // Cancelled or rescheduled.
        }
        catch (ObjectDisposedException)
        {
            // The component (or its circuit) is gone; nothing left to hide.
        }
    }
}
