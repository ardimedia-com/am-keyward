using System.Diagnostics;

namespace Am.Keyward.Ui.Blazor.App.Hosting;

/// <summary>
/// Evens out the response time of account forms whose work depends on whether an address has an account
/// (forgot password, registration): the real-account path generates a token and talks to the mail relay, the other
/// returns at once — a timing tell that enumerates accounts. Every answer waits until at least <see cref="Floor"/>
/// has passed since the form was received. Coarse on purpose ("constant-ish"): a relay slower than the floor still
/// shows, which is why mail failures are caught and the same answer is given either way.
/// </summary>
public static class AccountResponseTiming
{
    /// <summary>The minimum duration of such a response.</summary>
    public static readonly TimeSpan Floor = TimeSpan.FromMilliseconds(1200);

    /// <summary>Waits until <see cref="Floor"/> has passed since <paramref name="started"/>.</summary>
    public static async Task EnsureFloorAsync(long started, CancellationToken ct = default)
    {
        var remaining = Floor - Stopwatch.GetElapsedTime(started);
        if (remaining > TimeSpan.Zero)
        {
            try
            {
                await Task.Delay(remaining, ct);
            }
            catch (OperationCanceledException)
            {
                // The client went away; nothing to even out.
            }
        }
    }
}
