using System.Security.Cryptography;
using Am.Keyward.Core.Abstractions;

namespace Am.Keyward.Infrastructure.Crypto;

/// <summary>
/// A KEK provider holding a single 32-byte key-encryption-key in memory. It wraps/unwraps data keys
/// with AES-256-GCM (BCL primitive). File/Env providers load the key from outside the database and
/// construct this. AES-256-GCM is used for the wrap (authenticated) instead of RFC-3394 AES-KW, which
/// is not in the BCL; the chosen algorithm is recorded per value in <c>EncryptedValue.WrapAlg</c>.
/// </summary>
public sealed class StaticKekProvider : IKekProvider
{
    private const int KekSize = 32;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private static readonly byte[] WrapAad = "amkw-dek-wrap|1"u8.ToArray();

    private readonly byte[] _kek;

    public string KekId { get; }

    public StaticKekProvider(byte[] kek, string kekId)
    {
        ArgumentNullException.ThrowIfNull(kek);
        if (kek.Length != KekSize)
        {
            throw new ArgumentException($"KEK must be {KekSize} bytes.", nameof(kek));
        }

        if (string.IsNullOrWhiteSpace(kekId))
        {
            throw new ArgumentException("kekId required.", nameof(kekId));
        }

        _kek = (byte[])kek.Clone();
        KekId = kekId;
    }

    public ValueTask<byte[]> WrapAsync(byte[] dek, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(dek);
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var cipher = new byte[dek.Length];
        var tag = new byte[TagSize];
        using (var gcm = new AesGcm(_kek, TagSize))
        {
            gcm.Encrypt(nonce, dek, cipher, tag, WrapAad);
        }

        // wrapped = nonce(12) || tag(16) || cipher(len(dek))
        var wrapped = new byte[NonceSize + TagSize + cipher.Length];
        Buffer.BlockCopy(nonce, 0, wrapped, 0, NonceSize);
        Buffer.BlockCopy(tag, 0, wrapped, NonceSize, TagSize);
        Buffer.BlockCopy(cipher, 0, wrapped, NonceSize + TagSize, cipher.Length);
        return ValueTask.FromResult(wrapped);
    }

    public ValueTask<byte[]> UnwrapAsync(byte[] wrappedDek, string kekId, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(wrappedDek);
        if (!string.Equals(kekId, KekId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"KEK id mismatch (have '{KekId}', value needs '{kekId}').");
        }

        if (wrappedDek.Length < NonceSize + TagSize)
        {
            throw new CryptographicException("Wrapped DEK is malformed.");
        }

        var nonce = wrappedDek.AsSpan(0, NonceSize);
        var tag = wrappedDek.AsSpan(NonceSize, TagSize);
        var cipher = wrappedDek.AsSpan(NonceSize + TagSize);
        var dek = new byte[cipher.Length];
        using var gcm = new AesGcm(_kek, TagSize);
        gcm.Decrypt(nonce, cipher, tag, dek, WrapAad);
        return ValueTask.FromResult(dek);
    }
}
