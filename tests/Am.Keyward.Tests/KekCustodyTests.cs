using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Am.Keyward.Infrastructure.Crypto;

namespace Am.Keyward.Tests;

/// <summary>
/// File-based KEK custody on Windows: the key file and its folder are readable only by this installation (SYSTEM,
/// Administrators, the process identity, plus explicitly granted individual accounts) — never by a group such as
/// BUILTIN\Users, which a folder under %ProgramData% inherits — and the escrow passphrase has a minimum length.
/// </summary>
[TestClass]
[SupportedOSPlatform("windows")]
public class KekCustodyTests
{
    // Properties, not static fields: SecurityIdentifier throws on other platforms, and a failing type initializer
    // would fail the class instead of letting each test report itself inconclusive there.
    private static SecurityIdentifier Users => new(WellKnownSidType.BuiltinUsersSid, null);

    private static SecurityIdentifier Everyone => new(WellKnownSidType.WorldSid, null);

    // A fabricated IIS app-pool identity (S-1-5-82-…): an individual account an operator may grant explicitly.
    private static SecurityIdentifier SecondAppPool => new("S-1-5-82-1111111111-2222222222-3333333333-4444444444-555555555");

    [TestMethod, TestCategory("Crypto")]
    public void A_new_kek_folder_and_file_admit_only_system_administrators_and_this_process()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Inconclusive("DPAPI and NTFS access rules are Windows-only.");
            return;
        }

        var directory = NewDirectory();
        try
        {
            var (key, _, created) = DpapiKekFile.LoadOrCreate(directory);
            Assert.IsTrue(created);
            Assert.HasCount(32, key);

            AssertNarrowed(new DirectoryInfo(directory).GetAccessControl());
            AssertNarrowed(new FileInfo(DpapiKekFile.PathIn(directory)).GetAccessControl());
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [TestMethod, TestCategory("Crypto")]
    public void Loading_repairs_a_widened_folder_keeps_individual_grants_and_returns_the_same_key()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Inconclusive("DPAPI and NTFS access rules are Windows-only.");
            return;
        }

        var directory = NewDirectory();
        try
        {
            var (first, firstId, _) = DpapiKekFile.LoadOrCreate(directory);

            // Widen it the way a careless copy or a default %ProgramData% folder would: inheritance on, Users and
            // Everyone may read — plus a deliberate grant to a second installation's own identity.
            var folder = new DirectoryInfo(directory);
            var widened = folder.GetAccessControl();
            widened.SetAccessRuleProtection(isProtected: false, preserveInheritance: true);
            foreach (var sid in new[] { Users, Everyone, SecondAppPool })
            {
                widened.AddAccessRule(new FileSystemAccessRule(
                    sid, FileSystemRights.Read, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None, AccessControlType.Allow));
            }

            folder.SetAccessControl(widened);

            var (again, againId, created) = DpapiKekFile.LoadOrCreate(directory);
            Assert.IsFalse(created);
            CollectionAssert.AreEqual(first, again);
            Assert.AreEqual(firstId, againId);

            var folderRules = AssertNarrowed(folder.GetAccessControl());
            var fileRules = AssertNarrowed(new FileInfo(DpapiKekFile.PathIn(directory)).GetAccessControl());
            Assert.IsTrue(folderRules.Contains(SecondAppPool), "An explicit grant to an individual account survives on the folder ...");
            Assert.IsTrue(fileRules.Contains(SecondAppPool), "... and reaches the key file, so that installation can still read it.");
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [TestMethod, TestCategory("Unit")]
    public void Only_individual_accounts_count_as_individual()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Inconclusive("SecurityIdentifier is Windows-only.");
            return;
        }

        Assert.IsTrue(DpapiKekFile.IsIndividualAccount(SecondAppPool), "IIS app-pool identity");
        Assert.IsTrue(DpapiKekFile.IsIndividualAccount(new SecurityIdentifier("S-1-5-80-1-2-3-4-5")), "service identity");
        Assert.IsTrue(DpapiKekFile.IsIndividualAccount(new SecurityIdentifier("S-1-5-20")), "NETWORK SERVICE");
        Assert.IsTrue(DpapiKekFile.IsIndividualAccount(new SecurityIdentifier("S-1-5-21-1-2-3-1105")), "a domain account");

        Assert.IsFalse(DpapiKekFile.IsIndividualAccount(Users));
        Assert.IsFalse(DpapiKekFile.IsIndividualAccount(Everyone));
        Assert.IsFalse(DpapiKekFile.IsIndividualAccount(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null)));
        Assert.IsFalse(DpapiKekFile.IsIndividualAccount(new SecurityIdentifier("S-1-5-32-568")), "IIS_IUSRS — every app pool is in it");
        Assert.IsFalse(DpapiKekFile.IsIndividualAccount(new SecurityIdentifier("S-1-5-21-1-2-3-513")), "Domain Users");
    }

    [TestMethod, TestCategory("Crypto")]
    public void Escrow_requires_a_passphrase_of_at_least_twenty_characters_but_still_opens_older_blobs()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Inconclusive("The escrow helper is Windows-only.");
            return;
        }

        var kek = new byte[32];
        Random.Shared.NextBytes(kek);

        var tooShort = new string('x', DpapiKekEscrow.MinimumPassphraseLength - 1);
        Assert.IsTrue(DpapiKekEscrow.TooShort(tooShort));
        Assert.IsTrue(DpapiKekEscrow.TooShort(null));
        var refused = Assert.ThrowsExactly<ArgumentException>(() => DpapiKekEscrow.Wrap(kek, tooShort));
        StringAssert.Contains(refused.Message, "at least 20 characters");
        Assert.ThrowsExactly<ArgumentException>(() => DpapiKekEscrow.Wrap(kek, string.Empty));

        const string Passphrase = "correct horse battery staple";
        Assert.IsFalse(DpapiKekEscrow.TooShort(Passphrase));
        CollectionAssert.AreEqual(kek, DpapiKekEscrow.Unwrap(DpapiKekEscrow.Wrap(kek, Passphrase), Passphrase));
    }

    /// <summary>Asserts inheritance is off and no group may read; returns the identities that hold a grant.</summary>
    private static HashSet<SecurityIdentifier> AssertNarrowed(FileSystemSecurity security)
    {
        Assert.IsTrue(security.AreAccessRulesProtected, "Inheritance must be switched off.");

        var granted = security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .Where(r => r.AccessControlType == AccessControlType.Allow)
            .Select(r => (SecurityIdentifier)r.IdentityReference)
            .ToHashSet();

        Assert.IsTrue(granted.Contains(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null)), "SYSTEM");
        Assert.IsTrue(granted.Contains(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null)), "Administrators");
        Assert.IsTrue(granted.Contains(WindowsIdentity.GetCurrent().User!), "this process");
        Assert.IsFalse(granted.Contains(Users), "BUILTIN\\Users must not read the KEK.");
        Assert.IsFalse(granted.Contains(Everyone), "Everyone must not read the KEK.");
        return granted;
    }

    private static string NewDirectory() =>
        Path.Combine(Path.GetTempPath(), "keyward-kek-test-" + Guid.NewGuid().ToString("N"));
}
