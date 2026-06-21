using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Access;
using Am.Keyward.Core.Domain.Human;
using Am.Keyward.Core.Domain.Software;
using Am.Keyward.Core.Domain.ValueObjects;

namespace Am.Keyward.Tests;

[TestClass]
public class DomainTests
{
    private static EncryptedValue Sample() =>
        new([1, 2, 3], [4], [5], [6], "kek-1", "AES-KW", 1, 1);

    [TestMethod, TestCategory("Domain")]
    public void SecretKey_accepts_section_key_shape()
    {
        Assert.AreEqual("Shopify:AccessToken", SecretKey.Create("Shopify:AccessToken").Value);
        Assert.AreEqual("ConnectionStrings:Main", SecretKey.Create(" ConnectionStrings:Main ").Value);
    }

    [TestMethod, TestCategory("Domain")]
    public void SecretKey_rejects_invalid()
    {
        Assert.ThrowsExactly<ArgumentException>(() => SecretKey.Create(""));
        Assert.ThrowsExactly<ArgumentException>(() => SecretKey.Create("bad key with spaces"));
        Assert.ThrowsExactly<ArgumentException>(() => SecretKey.Create("Section:"));
    }

    [TestMethod, TestCategory("Domain")]
    public void EnvironmentName_default_set_is_dev_test_preview_prod()
    {
        CollectionAssert.AreEqual(
            new[] { "Development", "Test", "Preview", "Production" },
            EnvironmentName.DefaultSet.Select(e => e.Value).ToArray());
    }

    [TestMethod, TestCategory("Domain")]
    public void Project_rejects_user_owner()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            new Project(Guid.NewGuid(), Guid.NewGuid(), OwnerType.User, Guid.NewGuid(), "p", DateTimeOffset.UnixEpoch));
    }

    [TestMethod, TestCategory("Domain")]
    public void Personal_vault_must_be_tenant_less()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            new Vault(Guid.NewGuid(), Guid.NewGuid(), OwnerType.User, Guid.NewGuid(), ProtectionMode.ServerSide, "v", DateTimeOffset.UnixEpoch));

        var personal = new Vault(Guid.NewGuid(), null, OwnerType.User, Guid.NewGuid(), ProtectionMode.ServerSide, "v", DateTimeOffset.UnixEpoch);
        Assert.IsNull(personal.TenantId);
    }

    [TestMethod, TestCategory("Domain")]
    public void Org_vault_requires_tenant()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            new Vault(Guid.NewGuid(), null, OwnerType.Group, Guid.NewGuid(), ProtectionMode.ServerSide, "v", DateTimeOffset.UnixEpoch));
    }

    [TestMethod, TestCategory("Domain")]
    public void Project_environment_names_are_unique_case_insensitive()
    {
        var p = new Project(Guid.NewGuid(), Guid.NewGuid(), OwnerType.Tenant, Guid.NewGuid(), "p", DateTimeOffset.UnixEpoch);
        p.AddEnvironment(Guid.NewGuid(), EnvironmentName.Production, DateTimeOffset.UnixEpoch);
        Assert.ThrowsExactly<InvalidOperationException>(() =>
            p.AddEnvironment(Guid.NewGuid(), EnvironmentName.Create("production"), DateTimeOffset.UnixEpoch));
    }

    [TestMethod, TestCategory("Domain")]
    public void SoftwareSecret_keeps_one_value_per_environment_and_tracks_current_version()
    {
        var secret = new SoftwareSecret(Guid.NewGuid(), Guid.NewGuid(), SecretKey.Create("Shopify:AccessToken"), null, DateTimeOffset.UnixEpoch);
        var envId = Guid.NewGuid();

        var value = secret.SetValue(Guid.NewGuid(), envId, Guid.NewGuid(), Sample(), DateTimeOffset.UnixEpoch);
        Assert.HasCount(1, secret.Values);
        Assert.AreEqual(value.CurrentVersionId, value.Current.Id);
        Assert.AreEqual(1, value.Current.VersionNumber);

        secret.SetValue(Guid.NewGuid(), envId, Guid.NewGuid(), Sample(), DateTimeOffset.UnixEpoch);
        Assert.HasCount(1, secret.Values, "same environment reuses the SecretValue");
        Assert.HasCount(2, value.Versions);
        Assert.AreEqual(2, value.Current.VersionNumber);
    }

    [TestMethod, TestCategory("Domain")]
    public void AccessGrant_preserves_scope_and_changes_permission()
    {
        var scope = new GrantScope(GrantScopeKind.Environment, Guid.NewGuid());
        var grant = new AccessGrant(Guid.NewGuid(), Guid.NewGuid(), PrincipalType.Group, Guid.NewGuid(), scope, Permission.Read, null, DateTimeOffset.UnixEpoch);

        Assert.AreEqual(GrantScopeKind.Environment, grant.Scope.Kind);
        grant.ChangePermission(Permission.Manage);
        Assert.AreEqual(Permission.Manage, grant.Permission);
    }
}
