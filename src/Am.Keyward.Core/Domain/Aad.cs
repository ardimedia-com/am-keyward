using System.Text;

namespace Am.Keyward.Core.Domain;

/// <summary>
/// Builds the canonical Additional Authenticated Data (AAD) that binds an encrypted value to its exact
/// logical slot, so a ciphertext bundle cannot be moved between environments, versions, tenants, owners
/// or item kinds (AES-GCM authenticates the AAD, so a wrong slot fails to decrypt). The format is a
/// pipe-delimited UTF-8 string; every component is a Guid / enum name / integer and therefore cannot
/// contain the '|' delimiter, so the encoding is unambiguous. Format version 1.
/// </summary>
public static class Aad
{
    private const string Magic = "amkw";
    private const int AadFormatVersion = 1;

    /// <summary>AAD for a software-secret value version: Project → (environment) → secret → version.</summary>
    public static byte[] ForSoftwareSecretVersion(
        Guid tenantId, Guid projectId, Guid environmentId, Guid secretId, Guid versionId, int algVersion)
        => Build("sv", tenantId, ownerType: "-", ownerOrProjectId: projectId,
                 environmentId: environmentId, id: secretId, versionId: versionId, algVersion: algVersion);

    /// <summary>AAD for a vault item version: owner (tenant/group/user) → item → version (no environment).</summary>
    public static byte[] ForVaultItemVersion(
        Guid? tenantId, OwnerType ownerType, Guid ownerId, Guid itemId, Guid versionId, int algVersion)
        => Build("vi", tenantId, ownerType: ownerType.ToString(), ownerOrProjectId: ownerId,
                 environmentId: null, id: itemId, versionId: versionId, algVersion: algVersion);

    /// <summary>
    /// AAD for the per-subject PII encrypted in an audit-subject row (crypto-shredding). Binds the
    /// ciphertext to the subject's pseudonym, so an encrypted PII blob cannot be moved to another subject.
    /// </summary>
    public static byte[] ForAuditSubjectPii(Guid pseudonymId, int algVersion)
        => Build("as", tenantId: null, ownerType: "-", ownerOrProjectId: pseudonymId,
                 environmentId: null, id: pseudonymId, versionId: pseudonymId, algVersion: algVersion);

    private static byte[] Build(
        string slot, Guid? tenantId, string ownerType, Guid ownerOrProjectId,
        Guid? environmentId, Guid id, Guid versionId, int algVersion)
    {
        string[] parts =
        [
            Magic,
            AadFormatVersion.ToString(),
            slot,
            tenantId?.ToString("D") ?? "-",
            ownerType,
            ownerOrProjectId.ToString("D"),
            environmentId?.ToString("D") ?? "-",
            id.ToString("D"),
            versionId.ToString("D"),
            algVersion.ToString(),
        ];
        return Encoding.UTF8.GetBytes(string.Join('|', parts));
    }
}
