using System.Security.Cryptography;
using System.Text;
using Am.Keyward.Core.Domain;

namespace Am.Keyward.Infrastructure.Persistence;

/// <summary>
/// The canonical hash for one link of the per-tenant audit chain: SHA-256 over the entry's fields plus
/// the previous link's hash. Shared by the writer (<see cref="DbAuditSink"/>) and the verifier
/// (<see cref="DbAuditChainVerifier"/>) so they cannot drift. The fields are Guids / enum names / an
/// integer / an ISO-8601 timestamp, none of which can contain the '|' delimiter, so the encoding is
/// unambiguous.
/// </summary>
internal static class AuditChainHash
{
    public const string GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000";

    public static string Compute(
        Guid? tenantId,
        long sequence,
        AuditAction action,
        string resourceType,
        Guid? resourceId,
        Guid? actorPseudonymId,
        DateTimeOffset occurredAt,
        string previousHash)
    {
        var canonical = string.Join('|',
        [
            tenantId?.ToString("D") ?? "-",
            sequence.ToString(),
            action.ToString(),
            resourceType,
            resourceId?.ToString("D") ?? "-",
            actorPseudonymId?.ToString("D") ?? "-",
            occurredAt.ToString("O"),
            previousHash,
        ]);

        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }
}
