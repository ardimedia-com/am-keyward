using System.Security.Cryptography;
using Am.Keyward.Core.Domain;
using Am.Keyward.Infrastructure.Crypto;

namespace Am.Keyward.Tests;

[TestClass]
public class CryptoTests
{
    private static EnvelopeSecretBackend NewBackend() =>
        new(new StaticKekProvider(RandomNumberGenerator.GetBytes(32), "test-kek:v1"));

    private static byte[] SoftwareAad(Guid tenant, Guid project, Guid env, Guid secret, Guid version) =>
        Aad.ForSoftwareSecretVersion(tenant, project, env, secret, version, algVersion: 1);

    [TestMethod, TestCategory("Crypto")]
    public async Task Roundtrip_recovers_plaintext()
    {
        var backend = NewBackend();
        var aad = SoftwareAad(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid());
        var plaintext = "correct horse battery staple"u8.ToArray();

        var encrypted = await backend.ProtectAsync(plaintext, aad);
        var roundtripped = await backend.UnprotectAsync(encrypted, aad);

        CollectionAssert.AreEqual(plaintext, roundtripped);
        Assert.AreEqual("AES-256-GCM", encrypted.WrapAlg);
        Assert.AreEqual(1, encrypted.AlgVersion);
        Assert.AreEqual(1, encrypted.FormatVersion);
    }

    [TestMethod, TestCategory("Crypto")]
    public async Task Tampered_ciphertext_fails()
    {
        var backend = NewBackend();
        var aad = SoftwareAad(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid());
        var encrypted = await backend.ProtectAsync("secret"u8.ToArray(), aad);

        encrypted.Ciphertext[0] ^= 0xFF;

        await Assert.ThrowsAsync<CryptographicException>(async () => await backend.UnprotectAsync(encrypted, aad));
    }

    [TestMethod, TestCategory("Crypto")]
    public async Task Ciphertext_from_one_slot_cannot_be_decrypted_in_another()
    {
        // Same tenant/project/secret/version, different environment (Dev vs Prod): the AAD binds it.
        var backend = NewBackend();
        var tenant = Guid.NewGuid();
        var project = Guid.NewGuid();
        var secret = Guid.NewGuid();
        var version = Guid.NewGuid();
        var devEnv = Guid.NewGuid();
        var prodEnv = Guid.NewGuid();

        var encrypted = await backend.ProtectAsync("dev-value"u8.ToArray(), SoftwareAad(tenant, project, devEnv, secret, version));

        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await backend.UnprotectAsync(encrypted, SoftwareAad(tenant, project, prodEnv, secret, version)));
    }

    [TestMethod, TestCategory("Crypto")]
    public async Task Wrong_kek_id_is_rejected()
    {
        var backend = NewBackend();
        var aad = SoftwareAad(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid());
        var encrypted = await backend.ProtectAsync("x"u8.ToArray(), aad);

        var otherBackend = NewBackend(); // different random KEK + same id semantics but different key
        await Assert.ThrowsAsync<CryptographicException>(async () => await otherBackend.UnprotectAsync(encrypted, aad));
    }
}
