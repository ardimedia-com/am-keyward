using System.Security.Cryptography;
using Am.Keyward.Core.Abstractions;

namespace Am.Keyward.Infrastructure.Crypto;

/// <summary>
/// A KEK provider that holds several key-encryption-key versions: the <em>current</em> version (used to wrap
/// new data keys) plus any prior versions still needed to unwrap existing values during a rotation overlap
/// window. This is what makes KEK rotation workable — after introducing a new current version, existing
/// values keep resolving under their original version until a re-wrap job has migrated them (see
/// <see cref="IKekProvider.CanResolve"/> and the KEK-integrity verifier). Each version reuses the vetted
/// AES-256-GCM wrap/unwrap of <see cref="StaticKekProvider"/>.
/// </summary>
public sealed class KeyRingKekProvider : IKekProvider
{
    private readonly IReadOnlyDictionary<string, StaticKekProvider> _versions;
    private readonly StaticKekProvider _current;

    public string KekId => _current.KekId;

    /// <param name="currentKekId">The version used to wrap new values; must be present in <paramref name="keks"/>.</param>
    /// <param name="keks">All available versions (kekId -> 32-byte key): the current one and any prior versions
    /// still required to unwrap existing values during a rotation overlap.</param>
    public KeyRingKekProvider(string currentKekId, IReadOnlyDictionary<string, byte[]> keks)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(currentKekId);
        ArgumentNullException.ThrowIfNull(keks);
        if (keks.Count == 0)
        {
            throw new ArgumentException("The key ring must contain at least one KEK version.", nameof(keks));
        }

        if (!keks.ContainsKey(currentKekId))
        {
            throw new ArgumentException($"The current KEK id '{currentKekId}' is not in the key ring.", nameof(currentKekId));
        }

        _versions = keks.ToDictionary(kv => kv.Key, kv => new StaticKekProvider(kv.Value, kv.Key), StringComparer.Ordinal);
        _current = _versions[currentKekId];
    }

    /// <summary>
    /// Resolvable when a ring member has exactly this id, or when the id is the unqualified (pre-fingerprint) form
    /// of a member's id (<c>dpapi-file:v1</c> for <c>dpapi-file:v1:a1b2c3d4</c>, see
    /// <see cref="KekFingerprint.IsUnqualifiedFormOf"/>) - the same legacy acceptance <see cref="StaticKekProvider"/>
    /// has, so rows written before the fingerprint existed stay readable once a host moves to a key ring.
    /// </summary>
    public bool CanResolve(string kekId) =>
        _versions.ContainsKey(kekId) || LegacyCandidates(kekId).Any();

    public ValueTask<byte[]> WrapAsync(byte[] dek, CancellationToken ct = default) => _current.WrapAsync(dek, ct);

    public async ValueTask<byte[]> UnwrapAsync(byte[] wrappedDek, string kekId, CancellationToken ct = default)
    {
        if (_versions.TryGetValue(kekId, out var provider))
        {
            return await provider.UnwrapAsync(wrappedDek, kekId, ct).ConfigureAwait(false);
        }

        // A legacy id names only the FORMAT, so several members may claim it. AES-GCM authenticates: the member
        // that really sealed this DEK is the only one whose unwrap verifies, so a trial over the candidates is
        // exact (current key first - after an upgrade it is by far the most likely one).
        List<StaticKekProvider> candidates = [.. LegacyCandidates(kekId)];
        if (candidates.Count == 0)
        {
            throw new InvalidOperationException($"No KEK version '{kekId}' in the key ring (needed to unwrap this value).");
        }

        foreach (StaticKekProvider candidate in candidates)
        {
            try
            {
                return await candidate.UnwrapAsync(wrappedDek, candidate.KekId, ct).ConfigureAwait(false);
            }
            catch (CryptographicException)
            {
                // Not this member: try the next one.
            }
        }

        throw new CryptographicException(
            $"None of the {candidates.Count} key-ring member(s) of format '{kekId}' can unwrap this value.");
    }

    private IEnumerable<StaticKekProvider> LegacyCandidates(string kekId)
    {
        if (string.IsNullOrEmpty(kekId))
        {
            yield break;
        }

        if (KekFingerprint.IsUnqualifiedFormOf(kekId, _current.KekId))
        {
            yield return _current;
        }

        foreach (KeyValuePair<string, StaticKekProvider> member in _versions)
        {
            if (!ReferenceEquals(member.Value, _current) && KekFingerprint.IsUnqualifiedFormOf(kekId, member.Key))
            {
                yield return member.Value;
            }
        }
    }
}
