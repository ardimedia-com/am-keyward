using Am.Keyward.Core.Abstractions;
using Am.Keyward.Infrastructure.Auth;
using Am.Keyward.Infrastructure.Crypto;

namespace Am.Keyward.Infrastructure.Monitoring;

/// <summary>
/// The latest result of the periodic ops monitor, published for health checks to read. Updated atomically
/// by <see cref="OpsMonitorBackgroundService"/> so health endpoints never trigger a full database scan on
/// each poll. Registered as a singleton.
/// </summary>
public sealed class OpsHealthSnapshot
{
    /// <summary>One monitor run's findings. <paramref name="LastRunUtc"/> is <c>default</c> before the first run.</summary>
    /// <param name="LastRunUtc">When the run finished.</param>
    /// <param name="KekIntegrity">Every stored envelope resolves under an available KEK.</param>
    /// <param name="AuditChainIntact">Every tenant's audit chain verified (including the out-of-band anchors).</param>
    /// <param name="FirstBrokenAuditSequence">Where the first broken chain broke.</param>
    /// <param name="TokensExpiringSoon">Software-client tokens expiring within seven days.</param>
    /// <param name="KeyOwnership">The key-ownership verdict after this run's recheck.</param>
    /// <param name="BreakGlassTrail">Verification of the break-glass file; <c>null</c> when it could not be checked.</param>
    /// <param name="AuditAnchorTrail">Verification of the audit anchor file; <c>null</c> when anchoring is off.</param>
    public sealed record Reading(
        DateTimeOffset LastRunUtc,
        KekIntegrityReport? KekIntegrity,
        bool AuditChainIntact,
        long? FirstBrokenAuditSequence,
        int TokensExpiringSoon,
        KekIntegrityStatus KeyOwnership = KekIntegrityStatus.Unknown,
        HashChainVerification? BreakGlassTrail = null,
        HashChainVerification? AuditAnchorTrail = null);

    private volatile Reading _current = new(default, null, AuditChainIntact: true, null, 0);

    public Reading Current => _current;

    public void Publish(Reading reading) => _current = reading;
}
