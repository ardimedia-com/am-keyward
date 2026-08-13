using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace Am.Keyward.Infrastructure.Crypto;

/// <summary>
/// Disaster recovery for a <see cref="DpapiKekFile"/> key-encryption key: exports it as a portable,
/// passphrase-wrapped escrow blob and imports it back onto another machine.
///
/// <para><b>Why this exists.</b> The KEK file is a DPAPI blob with LOCAL-MACHINE scope, which can only ever be
/// unprotected on the machine that wrote it. Backing up <c>kek.bin</c> therefore protects ONLY against losing
/// the file on that same machine — if the app server dies or is re-imaged, the backup is unusable and every
/// stored secret is permanently unreadable, no matter how good the database backup is. Escrow closes that gap:
/// it takes the RAW key out of its machine binding and wraps it under an operator-chosen passphrase instead
/// (PBKDF2-SHA256, 600 000 iterations → AES-256-GCM), so it can be restored onto a NEW server.</para>
///
/// <para><b>Why this is a console command and not a page.</b> With local-machine DPAPI, any process already
/// running on the app server can unprotect the KEK — so an operator with server access gains nothing new here.
/// A web endpoint would be different: it would hand the KEK to anyone who reaches the app as an administrator,
/// which is strictly MORE than an administrator can do otherwise (they cannot read another user's personal
/// vault, but with the KEK plus a database copy they could decrypt everything offline). The capability stays
/// on the box, where it already exists.</para>
///
/// <para><b>The escrow blob is as strong as its passphrase.</b> It is not machine-bound by design — that is the
/// point — so it must be treated exactly like the KEK itself: long random passphrase, stored offline and apart
/// from both the database backup and the app server (whoever holds blob + passphrase + a database copy can
/// decrypt every secret).</para>
///
/// <para>A host wires this as the FIRST thing in <c>Program.cs</c>, before building the application, so it
/// still works on a server where the app cannot start (no database, no configuration) — which is exactly when
/// it is needed:</para>
/// <code>
/// if (DpapiKekEscrow.TryRunCommand(args, MyKekDirectory)) { return; }
/// </code>
/// </summary>
[SupportedOSPlatform("windows")]
public static class DpapiKekEscrow
{
    /// <summary>Marks the format so a future scheme can be told apart from this one.</summary>
    private const string BlobPrefix = "KEYWARD-KEK-ESCROW-v1:";

    /// <summary>PBKDF2-HMAC-SHA256 work factor (OWASP guidance for this KDF).</summary>
    private const int Pbkdf2Iterations = 600_000;

    private const int SaltSize = 16;
    private const int NonceSize = 12;   // AES-GCM standard
    private const int TagSize = 16;     // AES-GCM standard
    private const int WrapKeySize = 32; // AES-256

    /// <summary>The command-line switch that exports the escrow blob.</summary>
    public const string ExportSwitch = "--keyward-export-kek";

    /// <summary>The command-line switch that imports an escrow blob onto this machine.</summary>
    public const string ImportSwitch = "--keyward-import-kek";

    /// <summary>
    /// Handles the escrow console commands. Returns <c>true</c> when a command ran, so the host can exit
    /// without starting the application. Deliberately free of DI and configuration.
    /// </summary>
    /// <param name="args">The process arguments.</param>
    /// <param name="kekDirectory">The same directory the host passes to <see cref="DpapiKekFile.LoadOrCreate"/>.</param>
    public static bool TryRunCommand(string[] args, string kekDirectory)
    {
        ArgumentNullException.ThrowIfNull(args);

        string? command = args.FirstOrDefault(a =>
            a.Equals(ExportSwitch, StringComparison.OrdinalIgnoreCase)
            || a.Equals(ImportSwitch, StringComparison.OrdinalIgnoreCase));

        if (command is null)
        {
            return false;
        }

        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("FAILED: the KEK is a Windows DPAPI blob — this command only runs on the app server.");
            Environment.ExitCode = 1;
            return true;
        }

        Console.WriteLine($"AM KEYWARD KEK escrow — KEK file: {DpapiKekFile.PathIn(kekDirectory)}");
        Console.WriteLine();

        try
        {
            if (command.Equals(ExportSwitch, StringComparison.OrdinalIgnoreCase))
            {
                RunExport(kekDirectory);
            }
            else
            {
                RunImport(kekDirectory);
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"FAILED: {ex.Message}");
            Environment.ExitCode = 1;
        }

        return true;
    }

    /// <summary>
    /// Wraps a raw KEK under <paramref name="passphrase"/> into a portable text blob: PBKDF2-SHA256 derives a
    /// wrapping key from the passphrase, AES-256-GCM seals the KEK (the salt and nonce travel with the blob;
    /// GCM's tag makes a wrong passphrase fail loudly rather than yield garbage).
    /// </summary>
    public static string Wrap(byte[] kek, string passphrase)
    {
        ArgumentNullException.ThrowIfNull(kek);
        if (string.IsNullOrEmpty(passphrase))
        {
            throw new ArgumentException("A passphrase is required.", nameof(passphrase));
        }

        byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);
        byte[] wrappingKey = DeriveKey(passphrase, salt);

        byte[] cipher = new byte[kek.Length];
        byte[] tag = new byte[TagSize];
        using (AesGcm aes = new(wrappingKey, TagSize))
        {
            aes.Encrypt(nonce, kek, cipher, tag);
        }

        CryptographicOperations.ZeroMemory(wrappingKey);

        byte[] payload = [.. salt, .. nonce, .. tag, .. cipher];
        return BlobPrefix + Convert.ToBase64String(payload);
    }

    /// <summary>
    /// Reverses <see cref="Wrap"/>. Throws when the blob is malformed or the passphrase is wrong (AES-GCM
    /// authentication failure) — never returns a partially-correct key.
    /// </summary>
    public static byte[] Unwrap(string blob, string passphrase)
    {
        string trimmed = (blob ?? string.Empty).Trim();
        if (!trimmed.StartsWith(BlobPrefix, StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"Not a KEYWARD escrow blob (expected the prefix '{BlobPrefix}').");
        }

        byte[] payload = Convert.FromBase64String(trimmed[BlobPrefix.Length..]);
        if (payload.Length <= SaltSize + NonceSize + TagSize)
        {
            throw new InvalidOperationException("Escrow blob is truncated.");
        }

        ReadOnlySpan<byte> span = payload;
        byte[] salt = span[..SaltSize].ToArray();
        byte[] nonce = span.Slice(SaltSize, NonceSize).ToArray();
        byte[] tag = span.Slice(SaltSize + NonceSize, TagSize).ToArray();
        byte[] cipher = span[(SaltSize + NonceSize + TagSize)..].ToArray();

        byte[] wrappingKey = DeriveKey(passphrase, salt);
        byte[] kek = new byte[cipher.Length];
        try
        {
            using AesGcm aes = new(wrappingKey, TagSize);
            aes.Decrypt(nonce, cipher, tag, kek);
        }
        catch (CryptographicException)
        {
            throw new InvalidOperationException("Wrong passphrase, or the escrow blob is damaged.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrappingKey);
        }

        return kek;
    }

    /// <summary>
    /// A short, non-secret identifier of a KEK (SHA-256, first 8 hex chars) so an operator can confirm that
    /// the key imported onto the new server is the very key that was exported from the old one, without ever
    /// comparing key material by eye.
    /// </summary>
    public static string Fingerprint(byte[] kek) =>
        Convert.ToHexString(SHA256.HashData(kek))[..8].ToLowerInvariant();

    private static byte[] DeriveKey(string passphrase, byte[] salt) =>
        Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(passphrase), salt, Pbkdf2Iterations, HashAlgorithmName.SHA256, WrapKeySize);

    private static void RunExport(string directory)
    {
        string path = DpapiKekFile.PathIn(directory);
        if (!File.Exists(path))
        {
            throw new InvalidOperationException($"No KEK to export — '{path}' does not exist on this machine.");
        }

        byte[] kek = ProtectedData.Unprotect(File.ReadAllBytes(path), optionalEntropy: null, DataProtectionScope.LocalMachine);

        // Asked twice: a mistyped passphrase would produce an escrow nobody can ever open — and it would only
        // be discovered on the day it is needed.
        string passphrase = ReadPassphrase("Passphrase for the escrow blob: ");
        string confirmation = ReadPassphrase("Repeat the passphrase: ");
        if (!string.Equals(passphrase, confirmation, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("The passphrases do not match — nothing was exported.");
        }

        string blob = Wrap(kek, passphrase);
        string fingerprint = Fingerprint(kek);
        CryptographicOperations.ZeroMemory(kek);

        Console.WriteLine();
        Console.WriteLine($"KEK fingerprint: {fingerprint}");
        Console.WriteLine("Escrow blob (store OFFLINE, together with nothing else):");
        Console.WriteLine();
        Console.WriteLine(blob);
        Console.WriteLine();
        Console.WriteLine("Keep the passphrase somewhere other than the blob. Whoever has the blob, the passphrase");
        Console.WriteLine("AND a database copy can decrypt every stored secret.");
        Console.WriteLine("Restore drill: import it on a DIFFERENT machine and check the fingerprint matches —");
        Console.WriteLine("that is the only rehearsal that proves anything.");
    }

    private static void RunImport(string directory)
    {
        string path = DpapiKekFile.PathIn(directory);
        if (File.Exists(path))
        {
            throw new InvalidOperationException(
                $"'{path}' already exists — refusing to overwrite a live KEK. Move it aside first if this is "
                + "really intended (overwriting it makes every secret sealed under the current key unreadable).");
        }

        Console.Write("Paste the escrow blob: ");
        string blob = Console.ReadLine() ?? string.Empty;
        string passphrase = ReadPassphrase("Passphrase: ");

        byte[] kek = Unwrap(blob, passphrase);
        string fingerprint = Fingerprint(kek);

        Directory.CreateDirectory(directory);
        File.WriteAllBytes(path, ProtectedData.Protect(kek, optionalEntropy: null, DataProtectionScope.LocalMachine));
        CryptographicOperations.ZeroMemory(kek);

        Console.WriteLine();
        Console.WriteLine($"Imported. KEK fingerprint: {fingerprint}");
        Console.WriteLine($"Written (DPAPI, this machine): {path}");
        Console.WriteLine("Compare the fingerprint with the one printed at export — they must be identical.");
    }

    /// <summary>
    /// Reads a passphrase without echoing it. Falls back to a plain read when input is redirected (piped), so
    /// the command stays usable from a script or a restore drill.
    /// </summary>
    private static string ReadPassphrase(string prompt)
    {
        Console.Write(prompt);

        if (Console.IsInputRedirected)
        {
            string piped = Console.ReadLine() ?? string.Empty;
            Console.WriteLine();
            return piped;
        }

        StringBuilder builder = new();
        while (true)
        {
            ConsoleKeyInfo key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                return builder.ToString();
            }

            if (key.Key == ConsoleKey.Backspace)
            {
                if (builder.Length > 0)
                {
                    builder.Length--;
                }

                continue;
            }

            if (!char.IsControl(key.KeyChar))
            {
                builder.Append(key.KeyChar);
            }
        }
    }
}
