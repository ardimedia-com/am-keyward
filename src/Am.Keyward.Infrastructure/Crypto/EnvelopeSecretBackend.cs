using System.Security.Cryptography;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Domain.ValueObjects;

namespace Am.Keyward.Infrastructure.Crypto;

/// <summary>
/// Explicit envelope encryption (FormatVersion 1): a fresh 256-bit data key (DEK) encrypts each value
/// with AES-256-GCM, binding the supplied AAD (the logical slot); the DEK is then wrapped by the KEK via
/// <see cref="IKekProvider"/>. The database stores only the resulting <see cref="EncryptedValue"/>; the
/// KEK never enters the database. The DEK is zeroed from memory after use.
/// </summary>
public sealed class EnvelopeSecretBackend : ISecretBackend
{
    private const int DekSize = 32;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int AlgVersion = 1;
    private const int FormatVersion = 1;
    private const string WrapAlgName = "AES-256-GCM";

    private readonly IKekProvider _kek;

    public EnvelopeSecretBackend(IKekProvider kek) => _kek = kek;

    public async ValueTask<EncryptedValue> ProtectAsync(ReadOnlyMemory<byte> plaintext, ReadOnlyMemory<byte> aad, CancellationToken ct = default)
    {
        var dek = RandomNumberGenerator.GetBytes(DekSize);
        try
        {
            var nonce = RandomNumberGenerator.GetBytes(NonceSize);
            var cipher = new byte[plaintext.Length];
            var tag = new byte[TagSize];
            using (var gcm = new AesGcm(dek, TagSize))
            {
                gcm.Encrypt(nonce, plaintext.Span, cipher, tag, aad.Span);
            }

            var wrappedDek = await _kek.WrapAsync(dek, ct).ConfigureAwait(false);
            return new EncryptedValue(cipher, nonce, tag, wrappedDek, _kek.KekId, WrapAlgName, AlgVersion, FormatVersion);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }
    }

    public async ValueTask<byte[]> UnprotectAsync(EncryptedValue value, ReadOnlyMemory<byte> aad, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(value);
        // Pin the tag length to the constant we wrote with — never trust the stored (DB-writable) tag length.
        // A tamperer could otherwise shorten the tag to weaken forgery resistance.
        if (value.AuthTag.Length != TagSize)
        {
            throw new CryptographicException($"Unexpected authentication tag length {value.AuthTag.Length}; expected {TagSize}.");
        }

        var dek = await _kek.UnwrapAsync(value.WrappedDek, value.KekId, ct).ConfigureAwait(false);
        try
        {
            var plaintext = new byte[value.Ciphertext.Length];
            using var gcm = new AesGcm(dek, TagSize);
            gcm.Decrypt(value.Nonce, value.Ciphertext, value.AuthTag, plaintext, aad.Span);
            return plaintext;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }
    }
}
