using System.Security.Cryptography;
using System.Text;

namespace Am.Keyward.Infrastructure.Auth;

/// <summary>
/// Generates and hashes software-client tokens. Token shape: <c>amkw_&lt;prefix&gt;_&lt;secret&gt;</c>,
/// where the prefix is a non-secret, indexed lookup handle and the secret is high-entropy random. The
/// segments are lowercase hex so they never contain the <c>_</c> separator (Base64Url would). Only the
/// SHA-256 (hex) of the full token is persisted; a plain SHA-256 is appropriate because the token is
/// high-entropy (unlike a human password, no slow KDF is needed).
/// </summary>
public static class SoftwareClientTokenGenerator
{
    public const string Scheme = "amkw";
    private const int PrefixBytes = 6;   // 12 hex chars
    private const int SecretBytes = 32;  // 256 bits of entropy

    public sealed record GeneratedToken(string Token, string Prefix, string Hash);

    public static GeneratedToken Generate()
    {
        var prefix = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(PrefixBytes));
        var secret = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(SecretBytes));
        var token = $"{Scheme}_{prefix}_{secret}";
        return new GeneratedToken(token, prefix, Hash(token));
    }

    public static string Hash(string token) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    /// <summary>Extracts the lookup prefix from a presented token, or false if it is not a Keyward token.</summary>
    public static bool TryParsePrefix(string? token, out string prefix)
    {
        prefix = string.Empty;
        if (string.IsNullOrWhiteSpace(token))
        {
            return false;
        }

        var parts = token.Split('_');
        if (parts.Length != 3 || parts[0] != Scheme || parts[1].Length == 0 || parts[2].Length == 0)
        {
            return false;
        }

        prefix = parts[1];
        return true;
    }
}
