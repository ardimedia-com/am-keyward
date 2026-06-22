using System.Text;
using Am.Keyward.Core.Domain.ValueObjects;

namespace Am.Keyward.Tests;

/// <summary>
/// Telemetry-redaction guard: the encrypted envelope must never render its ciphertext, nonce, tag,
/// wrapped DEK or KEK id when logged. Structured loggers call <see cref="object.ToString"/> on a logged
/// object, so we assert that path is scrubbed.
/// </summary>
[TestClass]
public class RedactionTests
{
    [TestMethod, TestCategory("Unit")]
    public void EncryptedValue_ToString_is_redacted_and_leaks_nothing()
    {
        var value = new EncryptedValue(
            Ciphertext: Encoding.UTF8.GetBytes("SUPER-SECRET-CIPHERTEXT"),
            Nonce: Encoding.UTF8.GetBytes("NONCE-MATERIAL"),
            AuthTag: Encoding.UTF8.GetBytes("TAG-MATERIAL"),
            WrappedDek: Encoding.UTF8.GetBytes("WRAPPED-DEK-MATERIAL"),
            KekId: "kek-prod:v7",
            WrapAlg: "AES-256-GCM",
            AlgVersion: 1,
            FormatVersion: 1);

        var rendered = value.ToString();

        Assert.AreEqual("EncryptedValue { [REDACTED] }", rendered);
        // Records compose ToString of nested members, so guard the substrings too.
        StringAssert.Contains(rendered, "REDACTED");
        Assert.IsFalse(rendered.Contains("SECRET", StringComparison.OrdinalIgnoreCase), "ciphertext leaked");
        Assert.IsFalse(rendered.Contains("WRAPPED", StringComparison.OrdinalIgnoreCase), "wrapped DEK leaked");
        Assert.IsFalse(rendered.Contains("kek-prod", StringComparison.OrdinalIgnoreCase), "KEK id leaked");
    }
}
