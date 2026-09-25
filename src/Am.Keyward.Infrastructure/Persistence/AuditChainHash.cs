using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Audit;

namespace Am.Keyward.Infrastructure.Persistence;

/// <summary>
/// The canonical hash for one link of the per-tenant audit chain: SHA-256 over the entry's fields plus the
/// previous link's hash. Shared by the writer (<see cref="AuditChainInterceptor"/>) and the verifier
/// (<see cref="DbAuditChainVerifier"/>) so they cannot drift. The entry's <see cref="AuditEntry.HashVersion"/>
/// selects the canonical form, so a chain spanning versions verifies end to end.
/// </summary>
/// <remarks>
/// <para>Version 1: Guids / enum names / an integer / an ISO-8601 timestamp / the resource type, joined with
/// '|'. None of them contains the delimiter, so the encoding is unambiguous. Kept byte-for-byte as it was, or
/// every existing chain would stop verifying.</para>
/// <para>Version 2 adds the actor kind, the actor token and the free-text reason. Free text can contain '|' and
/// any other character, so every string field is length-prefixed (<c>&lt;utf8-byte-length&gt;:&lt;text&gt;</c>) and
/// null is encoded as <c>-</c>, which a length-prefixed value can never be. The version itself is the first
/// token, so a v1 and a v2 form of the same fields can never produce the same input.</para>
/// </remarks>
internal static class AuditChainHash
{
    public const string GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000";

    private const string Null = "-";

    /// <summary>The hash of <paramref name="entry"/> at <paramref name="sequence"/>, in the form of its hash version.</summary>
    public static string Compute(AuditEntry entry, long sequence, string previousHash) => entry.HashVersion switch
    {
        1 => ComputeV1(entry.TenantId, sequence, entry.Action, entry.ResourceType, entry.ResourceId,
            entry.ActorPseudonymId, entry.OccurredAt, previousHash),
        2 => ComputeV2(entry, sequence, previousHash),
        _ => throw new InvalidOperationException($"Unknown audit hash version {entry.HashVersion}."),
    };

    private static string ComputeV1(
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
            tenantId?.ToString("D") ?? Null,
            sequence.ToString(CultureInfo.InvariantCulture),
            action.ToString(),
            resourceType,
            resourceId?.ToString("D") ?? Null,
            actorPseudonymId?.ToString("D") ?? Null,
            occurredAt.ToString("O", CultureInfo.InvariantCulture),
            previousHash,
        ]);

        return Hash(canonical);
    }

    private static string ComputeV2(AuditEntry entry, long sequence, string previousHash)
    {
        var canonical = string.Join('|',
        [
            "2",
            entry.TenantId?.ToString("D") ?? Null,
            sequence.ToString(CultureInfo.InvariantCulture),
            entry.Action.ToString(),
            Text(entry.ResourceType),
            entry.ResourceId?.ToString("D") ?? Null,
            entry.ActorPseudonymId?.ToString("D") ?? Null,
            entry.OccurredAt.ToString("O", CultureInfo.InvariantCulture),
            entry.ActorKind?.ToString() ?? Null,
            entry.ActorTokenId?.ToString("D") ?? Null,
            Text(entry.Reason),
            previousHash,
        ]);

        return Hash(canonical);
    }

    private static string Text(string? value) =>
        value is null ? Null : $"{Encoding.UTF8.GetByteCount(value).ToString(CultureInfo.InvariantCulture)}:{value}";

    private static string Hash(string canonical) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
}
