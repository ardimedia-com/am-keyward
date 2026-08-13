using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace Am.Keyward.Infrastructure.Crypto;

/// <summary>
/// Loads (or, on first run, creates) the key-encryption key (KEK) from a DPAPI-protected file that lives
/// OUTSIDE the database — the recommended Windows key custody for a self-hosted deployment. A database
/// compromise alone then yields only ciphertext, because the KEK with which every stored secret's data key is
/// wrapped is not in the database. The host passes the returned key and id to <c>AddKeyward</c>.
///
/// <para><b>The host owns the path.</b> This helper deliberately takes the directory as an argument and
/// hardcodes nothing: where a key ring may live is a hosting decision (it must survive deploys and app-pool
/// recycles, e.g. under <c>%ProgramData%</c>, and never sit inside a deployed site folder that a release
/// mirrors away).</para>
///
/// <para><b>One KEK per set of data, not per install.</b> Two installs that read the SAME database (a preview
/// and a production instance sharing one catalog) MUST share one KEK file — different keys would make every
/// secret written by one unreadable to the other. Two installs with their OWN databases should have their own
/// directories.</para>
///
/// <para><b>KEK custody is operator-owned.</b> Losing this key is total, unrecoverable data loss for every
/// stored secret — an intact database backup is worthless without it. And copying the FILE is not a disaster
/// recovery plan: the blob is machine-bound (local-machine scope), so it can only ever be unprotected on the
/// machine that wrote it. Use <see cref="DpapiKekEscrow"/> to lift the raw key out of its machine binding
/// under a passphrase; that is the only artefact that restores onto a NEW server.</para>
///
/// Windows-only, by construction (DPAPI).
/// </summary>
[SupportedOSPlatform("windows")]
public static class DpapiKekFile
{
    /// <summary>Length of the generated key: AES-256.</summary>
    private const int KekSize = 32;

    /// <summary>Identifier (incl. format version) of a KEK produced by this helper.</summary>
    public const string KekId = "dpapi-file:v1";

    /// <summary>File name of the KEK inside the host's directory.</summary>
    public const string FileName = "kek.bin";

    /// <summary>The full path of the KEK file in <paramref name="directory"/> — what a status page reports.</summary>
    public static string PathIn(string directory) => Path.Combine(directory, FileName);

    /// <summary>
    /// Returns the KEK for <c>AddKeyward</c>, creating it on first use. When the file is absent a fresh
    /// 32-byte key is generated, DPAPI-protected (local-machine scope) and written; <c>Created</c> is then
    /// <c>true</c>, so the host can log the "back it up offline" warning exactly once.
    /// </summary>
    /// <param name="directory">The host-owned key directory; created when missing.</param>
    public static (byte[] Key, string KekId, bool Created) LoadOrCreate(string directory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);

        Directory.CreateDirectory(directory);
        string path = PathIn(directory);

        if (File.Exists(path))
        {
            byte[] key = ProtectedData.Unprotect(File.ReadAllBytes(path), optionalEntropy: null, DataProtectionScope.LocalMachine);
            return key.Length == KekSize
                ? (key, KekId, Created: false)
                : throw new InvalidOperationException($"The KEK at '{path}' is malformed ({key.Length} bytes, expected {KekSize}).");
        }

        byte[] fresh = RandomNumberGenerator.GetBytes(KekSize);
        File.WriteAllBytes(path, ProtectedData.Protect(fresh, optionalEntropy: null, DataProtectionScope.LocalMachine));
        return (fresh, KekId, Created: true);
    }
}
