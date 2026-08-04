using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain.Software;

namespace Am.Keyward.Infrastructure.Statistics;

/// <summary>
/// The in-memory half of per-secret read statistics: <see cref="Record"/> is called on every successful
/// software read of a secret value and only mutates a dictionary under a lock — no I/O, no exceptions
/// escaping — so the secret-read hot path never pays for statistics. <see cref="Drain"/> hands the
/// accumulated batch to the flush service and starts a fresh one. Singleton.
/// </summary>
public sealed class SecretReadAccumulator(IClock clock) : ISecretReadRecorder
{
    private readonly Lock gate = new();
    private Dictionary<(Guid SecretId, Guid EnvironmentId), PendingSecretRead> pending = [];

    public void Record(Guid tenantId, Guid secretId, Guid environmentId, SecretReadSource source)
    {
        var now = clock.UtcNow;
        lock (gate)
        {
            if (!pending.TryGetValue((secretId, environmentId), out var read))
            {
                pending[(secretId, environmentId)] = read = new PendingSecretRead(tenantId);
            }

            read.Register(now, source);
        }
    }

    /// <summary>Takes the current batch (empty list when nothing was recorded) and resets the accumulator.</summary>
    public IReadOnlyList<KeyValuePair<(Guid SecretId, Guid EnvironmentId), PendingSecretRead>> Drain()
    {
        Dictionary<(Guid, Guid), PendingSecretRead> drained;
        lock (gate)
        {
            if (pending.Count == 0)
            {
                return [];
            }

            drained = pending;
            pending = [];
        }

        return [.. drained];
    }
}

/// <summary>Everything recorded for one (secret, environment) since the last flush.</summary>
public sealed class PendingSecretRead(Guid tenantId)
{
    /// <summary>The owning tenant, carried along so the flush can stamp new rows without a lookup.</summary>
    public Guid TenantId { get; } = tenantId;

    public long Count { get; private set; }

    public DateTimeOffset LastReadAt { get; private set; }

    public SecretReadSource LastSource { get; private set; }

    public void Register(DateTimeOffset now, SecretReadSource source)
    {
        Count++;
        LastReadAt = now;
        LastSource = source;
    }
}
