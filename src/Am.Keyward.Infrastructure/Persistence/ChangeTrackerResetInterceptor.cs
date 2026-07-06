using Microsoft.EntityFrameworkCore.Diagnostics;

namespace Am.Keyward.Infrastructure.Persistence;

/// <summary>
/// Clears the change tracker after every successful SaveChanges. The <see cref="KeywardDbContext"/> is
/// registered scoped, and in a Blazor Server circuit that scope lives for the whole (potentially hours-long)
/// session. Without this, the change tracker would accumulate every entity touched across the circuit's
/// operations (memory growth) and identity-resolution would keep returning those stale, tracked instances on
/// later reads even after another circuit updated the row. Emptying the tracker after each save makes the
/// long-lived context behave like a short-lived one between operations: bounded memory and fresh reads.
///
/// Safe because no operation reuses a tracked entity across two SaveChanges calls (each service method is a
/// single load → mutate → save unit of work); the entity objects a method already materialized stay usable
/// after the clear (their values are not touched — they are only detached).
/// </summary>
public sealed class ChangeTrackerResetInterceptor : SaveChangesInterceptor
{
    public override int SavedChanges(SaveChangesCompletedEventData eventData, int result)
    {
        eventData.Context?.ChangeTracker.Clear();
        return result;
    }

    public override ValueTask<int> SavedChangesAsync(
        SaveChangesCompletedEventData eventData, int result, CancellationToken ct = default)
    {
        eventData.Context?.ChangeTracker.Clear();
        return ValueTask.FromResult(result);
    }
}
