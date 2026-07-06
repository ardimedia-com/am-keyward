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
    public async Task KeyRing_unwraps_prior_versions_during_rotation()
    {
        var keyA = RandomNumberGenerator.GetBytes(32);
        var keyB = RandomNumberGenerator.GetBytes(32);
        var dek = RandomNumberGenerator.GetBytes(32);

        var ringV1 = new KeyRingKekProvider("kek:v1", new Dictionary<string, byte[]> { ["kek:v1"] = keyA });
        var wrapped1 = await ringV1.WrapAsync(dek);

        // Rotate: v2 is current (wraps new values), but v1 is retained so existing values still resolve.
        var ringV2 = new KeyRingKekProvider("kek:v2", new Dictionary<string, byte[]> { ["kek:v1"] = keyA, ["kek:v2"] = keyB });
        Assert.AreEqual("kek:v2", ringV2.KekId);
        Assert.IsTrue(ringV2.CanResolve("kek:v1"));
        Assert.IsTrue(ringV2.CanResolve("kek:v2"));

        // The old value still unwraps under its original version, and new values wrap under v2.
        CollectionAssert.AreEqual(dek, await ringV2.UnwrapAsync(wrapped1, "kek:v1"));
        var wrapped2 = await ringV2.WrapAsync(dek);
        CollectionAssert.AreEqual(dek, await ringV2.UnwrapAsync(wrapped2, "kek:v2"));

        // A ring that has dropped v1 can no longer resolve the old value (the re-wrap job must run first).
        var ringV2Only = new KeyRingKekProvider("kek:v2", new Dictionary<string, byte[]> { ["kek:v2"] = keyB });
        Assert.IsFalse(ringV2Only.CanResolve("kek:v1"));
        await Assert.ThrowsExactlyAsync<InvalidOperationException>(async () => await ringV2Only.UnwrapAsync(wrapped1, "kek:v1"));
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
