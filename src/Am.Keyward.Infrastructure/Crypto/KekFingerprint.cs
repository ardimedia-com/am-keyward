using System.Security.Cryptography;

namespace Am.Keyward.Infrastructure.Crypto;

/// <summary>
/// A short, non-secret identifier of a key-encryption key, so two installations (or an export and its
/// import) can be compared without ever putting key material side by side.
///
/// <para>SHA-256 truncated to 8 hex characters. Not a secret: 32 bits of a hash preimage-resist nothing
/// back to a 256-bit key, which is why it is safe to print on a console, write into a log and store next to
/// the ciphertext it identifies.</para>
/// </summary>
public static class KekFingerprint
{
    /// <summary>Length of the hex fingerprint appended to a KEK id.</summary>
    public const int Length = 8;

    public static string Of(byte[] kek)
    {
        ArgumentNullException.ThrowIfNull(kek);
        return Convert.ToHexString(SHA256.HashData(kek))[..Length].ToLowerInvariant();
    }

    /// <summary>
    /// Builds a KEK id of the form <c>&lt;provider&gt;:&lt;version&gt;:&lt;fingerprint&gt;</c>. The
    /// fingerprint segment is what lets <see cref="StaticKekProvider.CanResolve"/> tell two keys of the SAME
    /// format apart — without it, a stored id identifies only the format and a foreign key looks resolvable.
    /// </summary>
    public static string Qualify(string formatId, byte[] kek)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(formatId);
        return $"{formatId}:{Of(kek)}";
    }

    /// <summary>
    /// Whether <paramref name="storedKekId"/> is the unqualified (pre-fingerprint) form of
    /// <paramref name="currentKekId"/> — e.g. <c>dpapi-file:v1</c> for <c>dpapi-file:v1:a1b2c3d4</c>.
    ///
    /// <para>Rows written before the fingerprint existed carry the bare format id, and there is no way to
    /// tell from the id alone whether they were written by THIS key. They are accepted, because refusing
    /// them would declare every pre-existing row unreadable on the day the package is updated. The canary
    /// (<see cref="Am.Keyward.Core.Domain.KekCanary"/>) is what covers this gap: it proves key ownership
    /// directly, so a legacy row cannot hide a foreign key.</para>
    /// </summary>
    public static bool IsUnqualifiedFormOf(string storedKekId, string currentKekId) =>
        !string.IsNullOrEmpty(storedKekId)
        && currentKekId.Length == storedKekId.Length + 1 + Length
        && currentKekId.StartsWith(storedKekId, StringComparison.Ordinal)
        && currentKekId[storedKekId.Length] == ':';
}
