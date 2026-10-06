using System.Text;
using Am.Keyward.Core.Application;

namespace Am.Keyward.Tests;

/// <summary>Decisions T15 A / T17 A (2026-10-06): one-time codes computed by KEYWARD itself, checked against RFC 6238.</summary>
[TestClass]
public class TotpTests
{
    // RFC 6238 appendix B: the seeds are the ASCII digits, 20/32/64 bytes for SHA-1/256/512, 8 digits, 30 s.
    private static readonly string Seed1 = Totp.EncodeBase32(Encoding.ASCII.GetBytes("12345678901234567890"));
    private static readonly string Seed256 = Totp.EncodeBase32(Encoding.ASCII.GetBytes("12345678901234567890123456789012"));
    private static readonly string Seed512 = Totp.EncodeBase32(Encoding.ASCII.GetBytes("1234567890123456789012345678901234567890123456789012345678901234"));

    [TestMethod, TestCategory("Unit")]
    [DataRow(59L, "94287082", "46119246", "90693936")]
    [DataRow(1111111109L, "07081804", "68084774", "25091201")]
    [DataRow(1111111111L, "14050471", "67062674", "99943326")]
    [DataRow(1234567890L, "89005924", "91819424", "93441116")]
    [DataRow(2000000000L, "69279037", "90698825", "38618901")]
    [DataRow(20000000000L, "65353130", "77737706", "47863826")]
    public void Codes_match_the_RFC_6238_test_vectors(long unix, string sha1, string sha256, string sha512)
    {
        var at = DateTimeOffset.FromUnixTimeSeconds(unix);
        Assert.AreEqual(sha1, Totp.Generate(new TotpSettings(Seed1, TotpAlgorithm.Sha1, 8), at).Code);
        Assert.AreEqual(sha256, Totp.Generate(new TotpSettings(Seed256, TotpAlgorithm.Sha256, 8), at).Code);
        Assert.AreEqual(sha512, Totp.Generate(new TotpSettings(Seed512, TotpAlgorithm.Sha512, 8), at).Code);
    }

    [TestMethod, TestCategory("Unit")]
    public void A_code_is_valid_until_the_end_of_its_period()
    {
        var code = Totp.Generate(new TotpSettings(Seed1), DateTimeOffset.FromUnixTimeSeconds(59));
        Assert.AreEqual(6, code.Code.Length);
        Assert.AreEqual(DateTimeOffset.FromUnixTimeSeconds(60), code.ValidUntil);
    }

    [TestMethod, TestCategory("Unit")]
    public void A_secret_is_read_the_way_websites_show_it()
    {
        // Grouped, lower case, with padding — as copied from a 2FA setup page.
        var grouped = string.Join(' ', Seed1.ToLowerInvariant().Chunk(4).Select(c => new string(c))) + "====";
        var settings = Totp.Parse(grouped);
        Assert.AreEqual(Seed1, settings.SecretBase32);
        Assert.AreEqual(TotpAlgorithm.Sha1, settings.Algorithm);
        Assert.AreEqual(6, settings.Digits);
        Assert.AreEqual(30, settings.PeriodSeconds);
    }

    [TestMethod, TestCategory("Unit")]
    public void An_otpauth_link_keeps_issuer_account_and_parameters()
    {
        var settings = Totp.Parse($"otpauth://totp/DHL%20MyBill:bvd%40bvd.li?secret={Seed256}&issuer=DHL%20MyBill&algorithm=SHA256&digits=8&period=60");
        Assert.AreEqual("DHL MyBill", settings.Issuer);
        Assert.AreEqual("bvd@bvd.li", settings.Account);
        Assert.AreEqual(TotpAlgorithm.Sha256, settings.Algorithm);
        Assert.AreEqual(8, settings.Digits);
        Assert.AreEqual(60, settings.PeriodSeconds);

        // The stored form reads back to the same setting, and so to the same code.
        var stored = Totp.Normalize($"otpauth://totp/DHL%20MyBill:bvd%40bvd.li?secret={Seed256}&issuer=DHL%20MyBill&algorithm=SHA256&digits=8&period=60");
        Assert.AreEqual(settings with { }, Totp.Parse(stored));
        var at = DateTimeOffset.FromUnixTimeSeconds(1234567890);
        Assert.AreEqual(Totp.Generate(settings, at), Totp.Generate(stored, at));
    }

    [TestMethod, TestCategory("Unit")]
    [DataRow("")]
    [DataRow("not a key!")]
    [DataRow("ABCDEFGH")] // 5 bytes: too short
    [DataRow("otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=1")]
    [DataRow("otpauth-migration://offline?data=abc")]
    [DataRow("otpauth://totp/x?issuer=nobody")]
    [DataRow("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=MD5")]
    [DataRow("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=4")]
    public void Unreadable_keys_are_refused_with_a_reason(string input)
    {
        var error = Assert.ThrowsExactly<ArgumentException>(() => Totp.Parse(input));
        Assert.IsFalse(string.IsNullOrWhiteSpace(error.Message));
        Assert.IsFalse(Totp.TryParse(input, out _));
    }

    [TestMethod, TestCategory("Unit")]
    public void A_login_stores_the_key_normalised_and_old_entries_read_without_one()
    {
        var json = LoginContent.ToJson("https://example.com", "me", "pw", "", Seed1.ToLowerInvariant());
        var fields = LoginContent.Parse(json);
        Assert.StartsWith("otpauth://totp/", fields.Totp);
        Assert.AreEqual(Seed1, Totp.Parse(fields.Totp).SecretBase32);

        // Content written before 0.27 has no totp property.
        Assert.AreEqual("", LoginContent.Parse("""{"url":"u","username":"n","password":"p","note":""}""").Totp);

        Assert.ThrowsExactly<ArgumentException>(() => LoginContent.ToJson("u", "n", "p", "", "not-a-key"));
        Assert.ThrowsExactly<ArgumentException>(() => LoginContent.EnsureValid("""{"url":"u","totp":"nope"}"""));
    }

    [TestMethod, TestCategory("Unit")]
    public void Import_reads_the_2FA_column_of_Bitwarden_and_1Password_exports()
    {
        var bitwarden = EdgePasswordCsv.Parse($"name,login_uri,login_username,login_password,notes,login_totp\r\nDHL,https://dhl.com,me,pw,,{Seed1}\r\n");
        Assert.AreEqual(Seed1, bitwarden.Single().Totp);

        var onePassword = EdgePasswordCsv.Parse($"title,url,username,password,notes,otpauth\r\nDHL,https://dhl.com,me,pw,,otpauth://totp/DHL?secret={Seed1}\r\n");
        Assert.AreEqual($"otpauth://totp/DHL?secret={Seed1}", onePassword.Single().Totp);

        // The browser format has no such column, so an export never carries a 2FA key.
        Assert.DoesNotContain("totp", EdgePasswordCsv.Write([new ImportedLogin("x", "u", "n", "p", "", Seed1)]));
    }
}
