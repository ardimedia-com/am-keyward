using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using Microsoft.Extensions.Logging;

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
/// <para><b>Only this installation may read the file.</b> Local-machine DPAPI lets ANY process on the machine
/// unprotect the blob once it can read the file, and a folder under <c>%ProgramData%</c> inherits
/// <c>BUILTIN\Users: Read</c> — so a neighbouring app pool on the same server could take the key. On every
/// <see cref="LoadOrCreate(string, ILogger?)"/> the folder and the file are therefore narrowed to SYSTEM,
/// BUILTIN\Administrators and the identity of the running process, with inheritance switched off
/// (<see cref="TryRestrictAccess"/>). Explicit grants to individual accounts — a second installation that shares
/// this KEK under its own identity, e.g. an IIS app-pool identity an operator added by hand — are kept; grants to
/// groups (Users, Authenticated Users, IIS_IUSRS, Everyone, …) are removed. When the process may not change the
/// ACL of an EXISTING folder or key (a folder created by an administrator, whose owner it is not) the key still
/// loads and a warning is logged. A NEW key file is different: it is created with its own explicit, protected
/// rules and fails closed when those cannot be applied (<see cref="TryCreateKeyFile"/>).</para>
///
/// <para><b>First run is exclusive.</b> The new key is written to a temporary file and renamed into place without
/// replacing an existing one, so two installations starting for the first time on one folder end up with ONE key:
/// the loser of the rename reads the winner's file instead of keeping a key that exists only in its memory.</para>
///
/// <para><b>No DPAPI entropy.</b> An <c>optionalEntropy</c> would have to live somewhere a local process can
/// read as well (the code or configuration of this app), so it adds little next to the ACL — and every existing
/// file would have to be migrated (read without, rewritten with). It is deliberately not used.</para>
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

    /// <summary>
    /// Identifier of the FORMAT a KEK produced by this helper has. On its own it does not identify the KEY —
    /// two different keys of this format share it — so <see cref="LoadOrCreate"/> returns it qualified with
    /// the key's fingerprint (<see cref="KekFingerprint.Qualify"/>). Rows written before that qualification
    /// existed carry the bare value; <see cref="StaticKekProvider"/> still accepts those.
    /// </summary>
    public const string FormatId = "dpapi-file:v1";

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
    public static (byte[] Key, string KekId, bool Created) LoadOrCreate(string directory) => LoadOrCreate(directory, logger: null);

    /// <summary>
    /// Returns the KEK for <c>AddKeyward</c>, creating it on first use — see <see cref="LoadOrCreate(string)"/>.
    /// Before the key is read or written, the folder (and an existing file) is narrowed to this installation
    /// (<see cref="TryRestrictAccess"/>); when that is not possible a warning goes to <paramref name="logger"/>
    /// (without a logger: to <see cref="Trace"/>) and an existing key is still returned. A key created by this call
    /// is written exclusively with protected rules and throws <see cref="InvalidOperationException"/> when it cannot
    /// be protected.
    /// </summary>
    /// <param name="directory">The host-owned key directory; created when missing.</param>
    /// <param name="logger">Receives the warning when the access rules cannot be narrowed; optional.</param>
    public static (byte[] Key, string KekId, bool Created) LoadOrCreate(string directory, ILogger? logger)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);

        Directory.CreateDirectory(directory);
        string path = PathIn(directory);

        // Narrow the folder FIRST, so whatever else lands in it later inherits the narrowed rules. The key file
        // itself does not depend on this: it is created with its own explicit, protected rules (below).
        RestrictAccessOrWarn(directory, logger);

        if (File.Exists(path))
        {
            return Load(path);
        }

        byte[] fresh = RandomNumberGenerator.GetBytes(KekSize);
        if (!TryCreateKeyFile(directory, ProtectedData.Protect(fresh, optionalEntropy: null, DataProtectionScope.LocalMachine)))
        {
            // Another process (or thread) created the key between our check and our write. Its file is complete
            // (the rename is atomic) and it is the key the database will be sealed with: use it, never ours.
            CryptographicOperations.ZeroMemory(fresh);
            return Load(path);
        }

        return (fresh, KekFingerprint.Qualify(FormatId, fresh), Created: true);
    }

    private static (byte[] Key, string KekId, bool Created) Load(string path)
    {
        byte[] key = ProtectedData.Unprotect(File.ReadAllBytes(path), optionalEntropy: null, DataProtectionScope.LocalMachine);
        if (key.Length != KekSize)
        {
            CryptographicOperations.ZeroMemory(key);
            throw new InvalidOperationException($"The KEK at '{path}' is malformed ({key.Length} bytes, expected {KekSize}).");
        }

        return (key, KekFingerprint.Qualify(FormatId, key), Created: false);
    }

    /// <summary>
    /// Writes a NEW key file exclusively and atomically: the DPAPI blob goes into a temporary file that is created
    /// with an explicit, protected access-control list (SYSTEM, Administrators, the identity of this process and
    /// any individual account the folder already grants, see <see cref="TryRestrictAccess"/>), and is then renamed
    /// to <see cref="FileName"/> without replacing an existing file. Readers therefore never see a half-written key,
    /// and two first starts on one folder cannot both keep their own key: the second rename fails and that caller
    /// gets <c>false</c>, so it re-reads the winner's file.
    ///
    /// <para><b>Fails closed.</b> When the protected rules cannot be applied, or do not verify on the written file,
    /// the temporary file is deleted and an <see cref="InvalidOperationException"/> is thrown: a new key never
    /// stays readable by a group behind a mere warning.</para>
    /// </summary>
    /// <returns><c>true</c> when this call created the key file; <c>false</c> when one already existed.</returns>
    internal static bool TryCreateKeyFile(string directory, byte[] protectedBlob)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        ArgumentNullException.ThrowIfNull(protectedBlob);

        string path = PathIn(directory);
        string temporary = Path.Combine(directory, $".{FileName}.{Guid.NewGuid():N}.tmp");
        HashSet<SecurityIdentifier> kept = AllowedIdentities(directory);

        try
        {
            FileSecurity security = new();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            foreach (SecurityIdentifier sid in kept)
            {
                security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, AccessControlType.Allow));
            }

            try
            {
                using FileStream stream = new FileInfo(temporary).Create(
                    FileMode.CreateNew, FileSystemRights.Write | FileSystemRights.ReadPermissions, FileShare.None,
                    bufferSize: 4096, FileOptions.WriteThrough, security);
                stream.Write(protectedBlob);
                stream.Flush(flushToDisk: true);
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or SystemException)
            {
                throw new InvalidOperationException(
                    $"KEYWARD: the new key file in '{directory}' could not be created with protected access rules "
                    + $"({ex.Message}). No key was written. Make sure this process may create files in that folder.", ex);
            }

            if (!Complies(new FileInfo(temporary).GetAccessControl(), kept))
            {
                throw new InvalidOperationException(
                    $"KEYWARD: the new key file in '{directory}' did not keep its protected access rules (SYSTEM, "
                    + "Administrators and this process only). No key was written.");
            }

            try
            {
                File.Move(temporary, path, overwrite: false);
                return true;
            }
            catch (IOException) when (File.Exists(path))
            {
                return false;   // lost the race: the winner's key is the key
            }
        }
        finally
        {
            try
            {
                File.Delete(temporary);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Best effort: a leftover temporary blob is still protected (its rules were set at creation).
            }
        }
    }

    /// <summary>
    /// The identities that may hold the key: SYSTEM, BUILTIN\Administrators, this process, and every individual
    /// account the folder (or an existing key file) grants explicitly. When those rules cannot be read, only the
    /// required three are returned, which is the safe direction.
    /// </summary>
    private static HashSet<SecurityIdentifier> AllowedIdentities(string directory)
    {
        HashSet<SecurityIdentifier> kept = [.. RequiredIdentities()];
        try
        {
            FileInfo file = new(PathIn(directory));
            IEnumerable<FileSystemAccessRule> explicitGrants = ExplicitAllowRules(new DirectoryInfo(directory).GetAccessControl());
            if (file.Exists)
            {
                explicitGrants = explicitGrants.Concat(ExplicitAllowRules(file.GetAccessControl()));
            }

            foreach (FileSystemAccessRule rule in explicitGrants)
            {
                if (rule.IdentityReference is SecurityIdentifier sid && IsIndividualAccount(sid))
                {
                    kept.Add(sid);
                }
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or SystemException)
        {
            // Not readable: keep the minimum set.
        }

        return kept;
    }

    private static SecurityIdentifier[] RequiredIdentities() =>
    [
        new(WellKnownSidType.LocalSystemSid, null),
        new(WellKnownSidType.BuiltinAdministratorsSid, null),
        WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException("The identity of the running process has no SID."),
    ];

    /// <summary>
    /// Narrows the access rules of <paramref name="directory"/> and of the KEK file in it (when present) to
    /// SYSTEM, BUILTIN\Administrators and the identity of the running process, with inheritance switched off.
    /// Explicit grants to individual accounts (local or domain accounts, IIS app-pool and service identities,
    /// LOCAL/NETWORK SERVICE) are kept, so a second installation sharing this KEK under its own identity keeps its
    /// access; every grant to a group is removed. Nothing is written when the rules already comply. Never throws:
    /// returns <c>false</c> with the reason when the rules could not be checked or changed — typically because the
    /// process is not the folder's owner and has no right to change its ACL; an administrator then narrows it once
    /// by hand, after which the check passes without writing.
    /// </summary>
    /// <param name="directory">The KEK directory (as passed to <see cref="LoadOrCreate(string, ILogger?)"/>).</param>
    /// <param name="problem">Why the rules could not be narrowed; <c>null</c> on success.</param>
    public static bool TryRestrictAccess(string directory, out string? problem)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);

        try
        {
            DirectoryInfo folder = new(directory);
            FileInfo file = new(PathIn(directory));
            DirectorySecurity folderSecurity = folder.GetAccessControl();

            // Explicit grants to individual accounts survive; the set is the same for folder and file, so an
            // account that may read the folder may also read the key file in it.
            HashSet<SecurityIdentifier> kept = AllowedIdentities(directory);

            if (!Complies(folderSecurity, kept))
            {
                DirectorySecurity narrowed = new();
                narrowed.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
                foreach (SecurityIdentifier sid in kept)
                {
                    narrowed.AddAccessRule(new FileSystemAccessRule(
                        sid, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                        PropagationFlags.None, AccessControlType.Allow));
                }

                folder.SetAccessControl(narrowed);
            }

            // Re-read: narrowing the folder re-propagated its rules onto the file.
            if (file.Exists && !Complies(file.GetAccessControl(), kept))
            {
                FileSecurity narrowed = new();
                narrowed.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
                foreach (SecurityIdentifier sid in kept)
                {
                    narrowed.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, AccessControlType.Allow));
                }

                file.SetAccessControl(narrowed);
            }

            problem = null;
            return true;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or InvalidOperationException or SystemException)
        {
            problem = ex.Message;
            return false;
        }
    }

    /// <summary>
    /// Whether <paramref name="sid"/> stands for ONE account rather than a group: LOCAL SERVICE, NETWORK SERVICE,
    /// a per-service or IIS app-pool virtual account, or a local/domain account or custom group created on the
    /// machine or in the domain (relative id 1000 or above — the well-known domain groups such as Domain Users are
    /// below). Built-in aliases (Users, IIS_IUSRS, …) and well-known groups (Everyone, Authenticated Users, …) are not.
    /// </summary>
    internal static bool IsIndividualAccount(SecurityIdentifier sid)
    {
        string value = sid.Value;
        if (value is "S-1-5-19" or "S-1-5-20")
        {
            return true;
        }

        if (value.StartsWith("S-1-5-80-", StringComparison.Ordinal) || value.StartsWith("S-1-5-82-", StringComparison.Ordinal))
        {
            return true;
        }

        return value.StartsWith("S-1-5-21-", StringComparison.Ordinal)
            && uint.TryParse(value[(value.LastIndexOf('-') + 1)..], out uint rid)
            && rid >= 1000;
    }

    private static IEnumerable<FileSystemAccessRule> ExplicitAllowRules(FileSystemSecurity security) =>
        security.GetAccessRules(includeExplicit: true, includeInherited: false, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .Where(r => r.AccessControlType == AccessControlType.Allow);

    /// <summary>Inheritance off, every identity in <paramref name="kept"/> holds a grant, and nobody outside it does.</summary>
    private static bool Complies(FileSystemSecurity security, HashSet<SecurityIdentifier> kept)
    {
        if (!security.AreAccessRulesProtected)
        {
            return false;
        }

        var grants = security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .Where(r => r.AccessControlType == AccessControlType.Allow)
            .ToList();
        return grants.All(r => r.IdentityReference is SecurityIdentifier sid && kept.Contains(sid))
            && kept.All(sid => grants.Any(r => sid.Equals(r.IdentityReference)));
    }

    private static void RestrictAccessOrWarn(string directory, ILogger? logger)
    {
        if (TryRestrictAccess(directory, out string? problem))
        {
            return;
        }

        if (logger is not null)
        {
            logger.LogWarning(
                "KEYWARD: the access rules of the KEK folder {Directory} could not be narrowed to SYSTEM, Administrators and "
                + "this process ({Problem}). Any local process that can read the key file can unprotect it (local-machine "
                + "DPAPI). Narrow the folder by hand: inheritance off, SYSTEM + Administrators + this app's identity only.",
                directory, problem);
        }
        else
        {
            Trace.TraceWarning(
                $"KEYWARD: the access rules of the KEK folder {directory} could not be narrowed to SYSTEM, Administrators "
                + $"and this process ({problem}). Any local process that can read the key file can unprotect it.");
        }
    }
}
