using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Access;
using Am.Keyward.Core.Domain.ValueObjects;

namespace Am.Keyward.Core.Abstractions;

/// <summary>Time source (injectable so logic is testable and timestamps are UTC).</summary>
public interface IClock
{
    DateTimeOffset UtcNow { get; }
}

/// <summary>The current authenticated principal (resolved from the host's auth, never client-supplied claims of tenancy).</summary>
public interface ICurrentUser
{
    Guid? UserId { get; }

    bool IsAuthenticated { get; }
}

/// <summary>The active tenant for this request/session (null = personal context). Server-authoritative.</summary>
public interface ICurrentTenant
{
    Guid? TenantId { get; }
}

/// <summary>
/// Sets the server-authoritative tenant scope for the current request/session. Called ONLY at the host
/// edge (API route binding, Blazor circuit, future token auth) — never from business logic, which must
/// treat tenancy as immutable for the duration of the operation.
/// </summary>
public interface ITenantScopeSetter
{
    void SetTenant(Guid? tenantId);
}

/// <summary>
/// Sets the server-authoritative current user for the request/session. Called ONLY at the host edge
/// (resolved from the authenticated principal), never from business logic. Drives personal-vault
/// isolation (the user-scoped query filter and SQL Server row-level security).
/// </summary>
public interface IUserScopeSetter
{
    void SetUser(Guid? userId);
}

/// <summary>
/// Wraps/unwraps per-secret data-encryption-keys (DEKs) using an external key-encryption-key (KEK).
/// The KEK never leaves the provider and is never stored in the application database.
/// </summary>
public interface IKekProvider
{
    /// <summary>Identifier (incl. key-version) of the KEK currently used for wrapping.</summary>
    string KekId { get; }

    /// <summary>
    /// Whether this provider can still unwrap DEKs wrapped under <paramref name="kekId"/>. During a KEK
    /// rotation more than one version is available (the overlap window); the backup/restore integrity job
    /// uses this to verify every stored <c>wrappedDek</c> resolves under an available KEK without paying an
    /// unwrap round-trip per row.
    /// </summary>
    bool CanResolve(string kekId);

    ValueTask<byte[]> WrapAsync(byte[] dek, CancellationToken ct = default);

    ValueTask<byte[]> UnwrapAsync(byte[] wrappedDek, string kekId, CancellationToken ct = default);
}

/// <summary>
/// Encrypts/decrypts secret material into/from the <see cref="EncryptedValue"/> envelope, binding the
/// ciphertext to its logical slot via the supplied AAD.
/// </summary>
public interface ISecretBackend
{
    ValueTask<EncryptedValue> ProtectAsync(ReadOnlyMemory<byte> plaintext, ReadOnlyMemory<byte> aad, CancellationToken ct = default);

    ValueTask<byte[]> UnprotectAsync(EncryptedValue value, ReadOnlyMemory<byte> aad, CancellationToken ct = default);
}

/// <summary>
/// What the application asks the audit sink to record. <see cref="ActorUserId"/> is the real actor; the
/// sink pseudonymizes it (via <see cref="IAuditSubjectDirectory"/>) before storing, and assigns the
/// sequence/hash and chains it.
/// </summary>
public sealed record AuditRequest(
    Guid? TenantId,
    AuditAction Action,
    string ResourceType,
    Guid? ResourceId,
    Guid? ActorUserId);

/// <summary>The actor's human-readable PII held (encrypted) for an audit subject; destroyed on erasure.</summary>
public sealed record AuditSubjectPii(string DisplayName, string? ExternalId);

/// <summary>
/// Maps an actor to a stable, opaque audit pseudonym and holds that actor's PII encrypted under a
/// per-subject key, so DSGVO erasure can crypto-shred the PII while the immutable audit chain keeps the
/// pseudonym. Installation-global (a subject is stable across tenants).
/// </summary>
public interface IAuditSubjectDirectory
{
    /// <summary>
    /// Finds or creates the pseudonym for <paramref name="subjectReference"/>, capturing its PII encrypted
    /// at rest. Returns <c>null</c> for an unattributed event (no subject reference). The new subject row is
    /// staged on the shared unit of work and persisted by the caller's SaveChanges.
    /// </summary>
    ValueTask<Guid?> ResolvePseudonymAsync(string? subjectReference, AuditSubjectPii pii, CancellationToken ct = default);

    /// <summary>Decrypts a subject's PII for an admin audit view; <c>null</c> if unknown or already erased.</summary>
    Task<AuditSubjectPii?> TryReadPiiAsync(Guid pseudonymId, CancellationToken ct = default);

    /// <summary>Crypto-shreds every pseudonym of a subject (destroys the PII). Returns how many were erased.</summary>
    Task<int> EraseAsync(string subjectReference, CancellationToken ct = default);
}

/// <summary>Append-only, single-writer, per-tenant hash-chained audit sink.</summary>
public interface IAuditSink
{
    ValueTask AppendAsync(AuditRequest request, CancellationToken ct = default);
}

/// <summary>The result of verifying a tenant's audit hash chain.</summary>
public sealed record AuditChainStatus(bool IsIntact, long EntriesChecked, long? FirstBrokenSequence, string? Detail);

/// <summary>Walks a tenant's audit chain and recomputes the hashes to detect tampering or gaps.</summary>
public interface IAuditChainVerifier
{
    Task<AuditChainStatus> VerifyAsync(Guid? tenantId, CancellationToken ct = default);
}

/// <summary>One stored envelope whose KEK id cannot be resolved by the current provider.</summary>
public sealed record KekIntegrityIssue(string ResourceType, Guid ResourceId, string KekId);

/// <summary>
/// The result of the backup/restore consistency job: how many encrypted slots were scanned and which (if
/// any) reference a KEK version the provider can no longer resolve — the signal that a DB was restored
/// without its matching KEK store, or that a KEK version was destroyed before its rows were re-wrapped.
/// </summary>
public sealed record KekIntegrityReport(long Checked, IReadOnlyList<KekIntegrityIssue> Unresolvable)
{
    public bool IsConsistent => Unresolvable.Count == 0;
}

/// <summary>
/// Verifies that every persisted <c>wrappedDek</c> resolves under an available <c>kekId</c>. Installation-
/// wide (across tenants), so it must run with a database login able to read all rows — by design the
/// least-privilege runtime login is hidden from cross-tenant rows by row-level security.
/// </summary>
public interface IKekIntegrityVerifier
{
    Task<KekIntegrityReport> VerifyAsync(CancellationToken ct = default);
}

/// <summary>Resolves the connection string per tenant (shared DB by default; DB-per-tenant later).</summary>
public interface ITenantConnectionResolver
{
    string ResolveConnectionString(Guid? tenantId);
}

/// <summary>
/// Centralized access policy: resolves whether a principal may perform an action on a scoped resource.
/// Named <c>IKeywardAccessPolicy</c> (not <c>IAuthorizationService</c>) so it does not collide with
/// ASP.NET Core's <c>Microsoft.AspNetCore.Authorization.IAuthorizationService</c> in an embedding host.
/// </summary>
public interface IKeywardAccessPolicy
{
    ValueTask<bool> IsAllowedAsync(Guid? userId, GrantScope resource, Permission action, CancellationToken ct = default);
}

/// <summary>
/// Whether an installation-global user may act within a tenant. Used at the host edge to gate the
/// server-authoritative tenant scope against a caller-supplied <c>{tenantId}</c> (e.g. the management API
/// route), so an authenticated user cannot target a tenant they do not belong to. A user is authorized for
/// a tenant if they hold a membership in it or are a system admin (the installation operator).
/// </summary>
public interface ITenantMembership
{
    ValueTask<bool> IsMemberAsync(Guid userId, Guid tenantId, CancellationToken ct = default);
}

/// <summary>One non-repudiable break-glass event for the external append-only sink.</summary>
public sealed record BreakGlassRecord(
    DateTimeOffset At,
    string Event,
    Guid GrantId,
    Guid? TenantId,
    string Scope,
    Guid RequesterUserId,
    Guid? ApproverUserId,
    string Reason);

/// <summary>
/// Append-only, out-of-band sink for break-glass events. It must live outside the application database so
/// the DB admin whose emergency access is being recorded cannot rewrite their own trail — the source of
/// non-repudiation. The file implementation hash-chains each line so deletion or edits are detectable.
/// </summary>
public interface IBreakGlassSink
{
    Task AppendAsync(BreakGlassRecord record, CancellationToken ct = default);
}

/// <summary>A request for emergency (break-glass) access to a server-side resource.</summary>
public sealed record RequestBreakGlassCommand(Guid? TenantId, GrantScope Scope, Guid RequesterUserId, string Reason);

/// <summary>
/// Dual-control emergency access. A System Admin requests access with a reason; a different System Admin
/// must approve it (and the approval is written to the out-of-band <see cref="IBreakGlassSink"/> plus the
/// audit chain) before it can be consumed for a single recovery within its validity window.
/// </summary>
public interface IBreakGlassService
{
    Task<Guid> RequestAsync(RequestBreakGlassCommand cmd, CancellationToken ct = default);

    Task ApproveAsync(Guid grantId, Guid approverUserId, CancellationToken ct = default);

    Task RejectAsync(Guid grantId, Guid approverUserId, CancellationToken ct = default);

    Task<IReadOnlyList<BreakGlassGrant>> ListPendingAsync(CancellationToken ct = default);

    /// <summary>Consume an approved, unexpired grant for a single recovery; throws if it is not usable.</summary>
    Task ConsumeAsync(Guid grantId, Guid actorUserId, CancellationToken ct = default);
}
