using System.Security.Cryptography;

namespace Am.Keyward.Core.Support;

/// <summary>
/// Generates strong random passwords from a cryptographic random source. Every password holds at least one
/// upper-case letter, lower-case letter, digit and symbol, so it passes the usual complexity rules. Characters that
/// are easy to confuse when read or typed (<c>0 O o 1 l I</c>) are left out, and so are symbols that break in
/// shells, URLs, JSON or connection strings (quotes, backslash, semicolon, space, brackets).
/// </summary>
public static class PasswordGenerator
{
    public const int DefaultLength = 20;

    public const int MinimumLength = 12;

    public const int MaximumLength = 128;

    private const string Upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    private const string Lower = "abcdefghijkmnpqrstuvwxyz";
    private const string Digits = "23456789";
    private const string Symbols = "!#$%&*+-=?@_";

    private static readonly string[] Classes = [Upper, Lower, Digits, Symbols];
    private static readonly string All = string.Concat(Classes);

    /// <summary>A new password of <paramref name="length"/> characters (12 to 128).</summary>
    public static string Generate(int length = DefaultLength)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(length, MinimumLength);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(length, MaximumLength);

        var chars = new char[length];

        // One of each class first, the rest from the whole set; then shuffle, so the guaranteed characters do not
        // sit at predictable positions. GetInt32 is unbiased (no modulo skew).
        for (var i = 0; i < length; i++)
        {
            var set = i < Classes.Length ? Classes[i] : All;
            chars[i] = set[RandomNumberGenerator.GetInt32(set.Length)];
        }

        for (var i = length - 1; i > 0; i--)
        {
            var j = RandomNumberGenerator.GetInt32(i + 1);
            (chars[i], chars[j]) = (chars[j], chars[i]);
        }

        return new string(chars);
    }
}
