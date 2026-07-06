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

    public bool CanResolve(string kekId) => _versions.ContainsKey(kekId);

    public ValueTask<byte[]> WrapAsync(byte[] dek, CancellationToken ct = default) => _current.WrapAsync(dek, ct);

    public ValueTask<byte[]> UnwrapAsync(byte[] wrappedDek, string kekId, CancellationToken ct = default) =>
        _versions.TryGetValue(kekId, out var provider)
            ? provider.UnwrapAsync(wrappedDek, kekId, ct)
            : throw new InvalidOperationException($"No KEK version '{kekId}' in the key ring (needed to unwrap this value).");
}
