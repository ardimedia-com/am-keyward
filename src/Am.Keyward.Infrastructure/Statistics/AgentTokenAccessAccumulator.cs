using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;

namespace Am.Keyward.Infrastructure.Statistics;

/// <summary>
/// The in-memory half of agent-token usage (<see cref="IAgentTokenAccessRecorder"/>): keeps only the LATEST use per
/// token — time and client address — under a lock, no I/O, nothing escaping. <see cref="TokenAccessFlushService"/>
/// drains it on every flush tick and writes <c>AgentTokens.LastUsedAt</c> / <c>LastUsedIp</c>, also when token
/// statistics are switched off (it is a security signal, not a statistic). Singleton.
/// </summary>
public sealed class AgentTokenAccessAccumulator(IClock clock) : IAgentTokenAccessRecorder
{
    private const int MaxIpLength = 64;

    private readonly Lock gate = new();
    private Dictionary<Guid, AgentTokenUse> pending = [];

    public void Record(Guid tokenId, string? ipAddress)
    {
        var now = clock.UtcNow;
        var ip = ipAddress?.Trim();
        if (string.IsNullOrEmpty(ip) || ip.Length > MaxIpLength)
        {
            ip = null;
        }

        lock (gate)
        {
            // Keep the previous address when this request carried none: «last seen from» stays informative.
            var previousIp = pending.TryGetValue(tokenId, out var previous) ? previous.IpAddress : null;
            pending[tokenId] = new AgentTokenUse(now, ip ?? previousIp);
        }
    }

    /// <summary>Takes the current batch (empty when nothing was recorded) and resets the accumulator.</summary>
    public IReadOnlyList<KeyValuePair<Guid, AgentTokenUse>> Drain()
    {
        Dictionary<Guid, AgentTokenUse> drained;
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

/// <summary>The latest use of one agent token since the last flush.</summary>
public sealed record AgentTokenUse(DateTimeOffset At, string? IpAddress);
