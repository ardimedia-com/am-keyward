using System.Numerics;

namespace Am.Keyward.Core.Support;

/// <summary>
/// Encodes a <see cref="Guid"/> as a fixed-length, 22-character Base62 string (alphabet 0-9 A-Z a-z) for use
/// in deep-link URLs. Base62 carries no word-break characters (no '-' or '_'), so a double-click selects the
/// whole id when copying it out of the address bar — unlike the hyphenated "D" GUID format, where a hyphen
/// ends the selection. The length is fixed at <see cref="Length"/>, so the round-trip is loss-free (a leading
/// zero digit is preserved rather than trimmed).
/// </summary>
public static class Base62Guid
{
    private const string Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    private const int Radix = 62;

    /// <summary>Fixed length of every encoded id — 22 Base62 digits cover a full 128-bit GUID.</summary>
    public const int Length = 22;

    public static string Encode(Guid value)
    {
        // The GUID's 16 bytes read as one unsigned big-endian 128-bit integer. The byte order is arbitrary as
        // long as Encode and TryDecode agree — both use the big-endian layout.
        var magnitude = new BigInteger(value.ToByteArray(bigEndian: true), isUnsigned: true, isBigEndian: true);
        Span<char> buffer = stackalloc char[Length];
        for (var i = Length - 1; i >= 0; i--)
        {
            magnitude = BigInteger.DivRem(magnitude, Radix, out var digit);
            buffer[i] = Alphabet[(int)digit];
        }

        return new string(buffer);
    }

    /// <summary>Parses an id produced by <see cref="Encode"/>. False (and <see cref="Guid.Empty"/>) for a null,
    /// wrong-length, out-of-alphabet, or out-of-range (&gt; 128-bit) input — never throws.</summary>
    public static bool TryDecode(string? text, out Guid value)
    {
        value = Guid.Empty;
        if (text is null || text.Length != Length)
        {
            return false;
        }

        var magnitude = BigInteger.Zero;
        foreach (var c in text)
        {
            var digit = DigitOf(c);
            if (digit < 0)
            {
                return false;
            }

            magnitude = magnitude * Radix + digit;
        }

        // 22 Base62 digits can encode more than 2^128 — reject anything that doesn't fit into 16 bytes.
        var bytes = magnitude.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (bytes.Length > 16)
        {
            return false;
        }

        Span<byte> full = stackalloc byte[16];
        bytes.CopyTo(full[(16 - bytes.Length)..]);
        value = new Guid(full, bigEndian: true);
        return true;
    }

    private static int DigitOf(char c) => c switch
    {
        >= '0' and <= '9' => c - '0',
        >= 'A' and <= 'Z' => c - 'A' + 10,
        >= 'a' and <= 'z' => c - 'a' + 36,
        _ => -1,
    };
}
