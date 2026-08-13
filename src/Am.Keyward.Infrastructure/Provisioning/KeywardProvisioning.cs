using Am.Keyward.Core.Abstractions;

namespace Am.Keyward.Infrastructure.Provisioning;

/// <summary>
/// What the HOST must tell the provisioning diagnostics about itself. All of it is host-owned by nature: its
/// master switch, which tenant it seeds, where it keeps the key, and which environments must have Keyward
/// running at all.
/// </summary>
public sealed class KeywardProvisioningOptions
{
    /// <summary>
    /// The host's master switch. The diagnostics exist precisely to explain an environment where Keyward is
    /// OFF, so this is passed in rather than inferred — and the whole service must work with no Keyward
    /// service registered at all.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>The single tenant a company-wide host seeds, so the tenant probe knows what to look for.</summary>
    public Guid TenantId { get; set; }

    /// <summary>Its display name, for the technical chip.</summary>
    public string TenantName { get; set; } = string.Empty;

    /// <summary>Configuration key of the runtime connection string. Default <c>Keyward</c>.</summary>
    public string ConnectionStringName { get; set; } = "Keyward";

    /// <summary>
    /// The directory holding the KEK file, for hosts using the packaged DPAPI custody
    /// (<c>DpapiKekFile</c>). Leave <c>null</c> when the key comes from a KMS/HSM provider — the KEK check
    /// then reports <see cref="KeywardCheckOutcome.KekNotFileBased"/> instead of a missing file.
    /// </summary>
    public string? KekDirectory { get; set; }

    /// <summary>
    /// The host's policy: is Keyward expected to run in this environment? Defaults to "Development optional,
    /// everything else required", which fails safe — an unknown environment is treated as one that must have
    /// Keyward provisioned.
    /// </summary>
    public Func<IKeywardHostEnvironment, KeywardExpectation>? Expectation { get; set; }
}

/// <summary>
/// The bit of the hosting environment Keyward's host-side helpers need — the environment NAME (which selects
/// the secrets a machine reads and the settings overlay an operator edits) and whether it is Development.
/// One port for both concerns, so a host registers it once.
/// </summary>
public interface IKeywardHostEnvironment
{
    /// <summary>Development / Test / Preview / Production / … — must match Keyward's environment names.</summary>
    string EnvironmentName { get; }

    /// <summary>Whether this is the Development environment.</summary>
    bool IsDevelopment { get; }
}
