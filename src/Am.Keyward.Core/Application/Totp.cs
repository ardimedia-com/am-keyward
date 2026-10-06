using System.Security.Cryptography;
using System.Text;

namespace Am.Keyward.Core.Application;

/// <summary>The hash a TOTP code is computed with (RFC 6238 allows SHA-1, SHA-256 and SHA-512).</summary>
public enum TotpAlgorithm
{
    Sha1,
    Sha256,
    Sha512,
}

/// <summary>
/// A time-based one-time password setting (RFC 6238) as an authenticator app holds it: the shared secret in Base32 plus
/// the hash, the number of digits and the period. <see cref="Issuer"/> and <see cref="Account"/> are labels only.
/// </summary>
public sealed record TotpSettings(
    string SecretBase32,
    TotpAlgorithm Algorithm = TotpAlgorithm.Sha1,
    int Digits = 6,
    int PeriodSeconds = 30,
    string? Issuer = null,
    string? Account = null);

/// <summary>A one-time code and the moment it stops being valid.</summary>
public sealed record TotpCode(string Code, DateTimeOffset ValidUntil);

/// <summary>
/// Time-based one-time passwords (RFC 6238, decision T17 A): parses what a website hands out when 2FA is switched on —
/// the Base32 secret or the <c>otpauth://totp/…</c> link inside its QR code —, normalises it to an <c>otpauth://</c> link
/// for storage, and computes the current code. Pure computation over the BCL; verified against the RFC 6238 test vectors.
/// </summary>
public static class Totp
{
    private const string Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    // Shorter secrets are not used by real services and would make the code guessable (RFC 4226 asks for 128 bits,
    // 80 bits is the common floor).
    private const int MinimumSecretBytes = 10;

    /// <summary>Reads a Base32 secret or an <c>otpauth://totp/…</c> link. Throws <see cref="ArgumentException"/> with a reason.</summary>
    public static TotpSettings Parse(string input)
    {
        var text = input?.Trim() ?? "";
        if (text.Length == 0)
        {
            throw new ArgumentException("The 2FA key is empty.");
        }

        if (text.StartsWith("otpauth-migration:", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("This is a Google Authenticator export of several accounts. Use the QR code the website shows when 2FA is switched on.");
        }

        if (text.StartsWith("otpauth://hotp/", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Counter-based codes (HOTP) are not supported, only time-based ones (TOTP).");
        }

        return text.StartsWith("otpauth://", StringComparison.OrdinalIgnoreCase) ? ParseUri(text) : FromSecret(text);
    }

    /// <summary>Like <see cref="Parse"/>, without throwing.</summary>
    public static bool TryParse(string? input, out TotpSettings? settings)
    {
        try
        {
            settings = Parse(input ?? "");
            return true;
        }
        catch (ArgumentException)
        {
            settings = null;
            return false;
        }
    }

    /// <summary>The stored form: an <c>otpauth://totp/…</c> link with every parameter spelled out.</summary>
    public static string Normalize(string input) => ToUri(Parse(input));

    public static string ToUri(TotpSettings settings)
    {
        var issuer = string.IsNullOrWhiteSpace(settings.Issuer) ? null : settings.Issuer.Trim();
        var account = string.IsNullOrWhiteSpace(settings.Account) ? null : settings.Account.Trim();
        var label = (issuer, account) switch
        {
            (not null, not null) => $"{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(account)}",
            (not null, null) => Uri.EscapeDataString(issuer),
            (null, not null) => Uri.EscapeDataString(account),
            _ => "KEYWARD",
        };

        var query = new StringBuilder()
            .Append("secret=").Append(settings.SecretBase32)
            .Append("&algorithm=").Append(settings.Algorithm switch
            {
                TotpAlgorithm.Sha256 => "SHA256",
                TotpAlgorithm.Sha512 => "SHA512",
                _ => "SHA1",
            })
            .Append("&digits=").Append(settings.Digits)
            .Append("&period=").Append(settings.PeriodSeconds);
        if (issuer is not null)
        {
            query.Append("&issuer=").Append(Uri.EscapeDataString(issuer));
        }

        return $"otpauth://totp/{label}?{query}";
    }

    /// <summary>The code valid at <paramref name="at"/> for a stored setting (link or secret).</summary>
    public static TotpCode Generate(string stored, DateTimeOffset at) => Generate(Parse(stored), at);

    public static TotpCode Generate(TotpSettings settings, DateTimeOffset at)
    {
        var unix = at.ToUnixTimeSeconds();
        var step = unix / settings.PeriodSeconds;
        var validUntil = DateTimeOffset.FromUnixTimeSeconds((step + 1) * settings.PeriodSeconds);

        Span<byte> counter = stackalloc byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(counter, step);

        var key = DecodeBase32(settings.SecretBase32);
        try
        {
            byte[] hash = settings.Algorithm switch
            {
                TotpAlgorithm.Sha256 => HMACSHA256.HashData(key, counter),
                TotpAlgorithm.Sha512 => HMACSHA512.HashData(key, counter),
                _ => HMACSHA1.HashData(key, counter),
            };

            // Dynamic truncation (RFC 4226 §5.3).
            var offset = hash[^1] & 0x0F;
            var binary = ((hash[offset] & 0x7F) << 24)
                | (hash[offset + 1] << 16)
                | (hash[offset + 2] << 8)
                | hash[offset + 3];
            var code = binary % (int)Math.Pow(10, settings.Digits);
            return new TotpCode(code.ToString().PadLeft(settings.Digits, '0'), validUntil);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <summary>Base32 (RFC 4648) without padding — the form authenticator apps use.</summary>
    public static string EncodeBase32(ReadOnlySpan<byte> data)
    {
        var result = new StringBuilder((data.Length * 8 + 4) / 5);
        int buffer = 0, bits = 0;
        foreach (var b in data)
        {
            buffer = (buffer << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                result.Append(Base32Alphabet[(buffer >> (bits - 5)) & 31]);
                bits -= 5;
            }
        }

        if (bits > 0)
        {
            result.Append(Base32Alphabet[(buffer << (5 - bits)) & 31]);
        }

        return result.ToString();
    }

    private static TotpSettings FromSecret(string secret, TotpAlgorithm algorithm = TotpAlgorithm.Sha1, int digits = 6, int period = 30, string? issuer = null, string? account = null)
    {
        // Websites show the secret in groups («abcd efgh …»), sometimes lower case or with padding.
        var cleaned = new string([.. secret.Where(c => !char.IsWhiteSpace(c) && c != '-')]).TrimEnd('=').ToUpperInvariant();
        if (cleaned.Length == 0 || cleaned.Any(c => !Base32Alphabet.Contains(c)))
        {
            throw new ArgumentException("That is not a 2FA key: it consists of the letters A–Z and the digits 2–7 (or is an otpauth:// link).");
        }

        var bytes = DecodeBase32(cleaned);
        var length = bytes.Length;
        CryptographicOperations.ZeroMemory(bytes);
        if (length < MinimumSecretBytes)
        {
            throw new ArgumentException("The 2FA key is too short — copy it completely.");
        }

        if (digits is < 6 or > 8)
        {
            throw new ArgumentException("A one-time code has 6 to 8 digits.");
        }

        if (period is < 10 or > 300)
        {
            throw new ArgumentException("A one-time code changes every 10 to 300 seconds.");
        }

        return new TotpSettings(cleaned, algorithm, digits, period, issuer, account);
    }

    private static TotpSettings ParseUri(string text)
    {
        if (!Uri.TryCreate(text, UriKind.Absolute, out var uri) || !string.Equals(uri.Host, "totp", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("That otpauth link cannot be read.");
        }

        var parameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var pair in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = pair.IndexOf('=');
            var name = Uri.UnescapeDataString(eq >= 0 ? pair[..eq] : pair);
            parameters[name] = eq >= 0 ? Uri.UnescapeDataString(pair[(eq + 1)..].Replace('+', ' ')) : "";
        }

        if (!parameters.TryGetValue("secret", out var secret) || string.IsNullOrWhiteSpace(secret))
        {
            throw new ArgumentException("The otpauth link has no secret.");
        }

        var algorithm = parameters.GetValueOrDefault("algorithm")?.ToUpperInvariant() switch
        {
            null or "" or "SHA1" => TotpAlgorithm.Sha1,
            "SHA256" => TotpAlgorithm.Sha256,
            "SHA512" => TotpAlgorithm.Sha512,
            var other => throw new ArgumentException($"The hash «{other}» is not supported (SHA1, SHA256, SHA512)."),
        };
        var digits = int.TryParse(parameters.GetValueOrDefault("digits"), out var d) ? d : 6;
        var period = int.TryParse(parameters.GetValueOrDefault("period"), out var p) ? p : 30;

        // The label is «Issuer:account» (either part optional); an issuer parameter wins over the label's.
        var label = Uri.UnescapeDataString(uri.AbsolutePath.TrimStart('/'));
        string? labelIssuer = null, account = label.Length > 0 ? label : null;
        var colon = label.IndexOf(':');
        if (colon >= 0)
        {
            labelIssuer = label[..colon].Trim();
            account = label[(colon + 1)..].Trim();
        }

        var issuer = parameters.GetValueOrDefault("issuer") is { Length: > 0 } given ? given : labelIssuer;
        return FromSecret(secret, algorithm, digits, period, issuer, account);
    }

    private static byte[] DecodeBase32(string base32)
    {
        var output = new byte[base32.Length * 5 / 8];
        int buffer = 0, bits = 0, index = 0;
        foreach (var c in base32)
        {
            buffer = (buffer << 5) | Base32Alphabet.IndexOf(c);
            bits += 5;
            if (bits >= 8)
            {
                output[index++] = (byte)(buffer >> (bits - 8));
                bits -= 8;
            }
        }

        return output;
    }
}
