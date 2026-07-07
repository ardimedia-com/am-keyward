namespace Am.Keyward.Core.Domain.Software;

/// <summary>
/// A credential a deployed piece of software presents (as a Bearer token) to read its own secrets. It is
/// scoped to exactly one (project, environment) so a leaked token cannot read another environment. Only a
/// hash of the token is stored — the plaintext is shown once, at issuance; <see cref="TokenPrefix"/> is a
/// non-secret lookup handle. Tokens expire, can be rotated (new secret on the same record) and revoked.
/// A token can also exist as a <b>pending placeholder</b> (auto-created per environment, no prefix/hash yet
/// — see <see cref="CreatePending"/>): it cannot authenticate until its first value is minted via
/// <see cref="Rotate"/>. The record carries <see cref="TenantId"/> so that, once authenticated, the request
/// runs in the token's tenant scope; the table itself is installation-global (looked up before the tenant
/// is known).
/// </summary>
public sealed class SoftwareClientToken
{
    public Guid Id { get; private set; }
    public Guid TenantId { get; private set; }
    public Guid ProjectId { get; private set; }
    public Guid EnvironmentId { get; private set; }
    public string Name { get; private set; }

    /// <summary>Free-text note (e.g. where the token is deployed); never secret.</summary>
    public string Note { get; private set; }

    /// <summary>Non-secret, indexed lookup handle (the leading segment of the token).</summary>
    public string TokenPrefix { get; private set; }

    /// <summary>SHA-256 (hex) of the full token string. The plaintext token is never stored.</summary>
    public string TokenHash { get; private set; }

    public Guid? CreatedBy { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }
    public DateTimeOffset? ExpiresAt { get; private set; }
    public DateTimeOffset? LastRotatedAt { get; private set; }
    public DateTimeOffset? RevokedAt { get; private set; }

    /// <summary>
    /// Days-left value of the last expiry notice e-mailed for this token (dedupe for the notification
    /// schedule); null when none was sent for the current validity window. Rotation resets it.
    /// </summary>
    public int? LastExpiryNoticeDaysLeft { get; private set; }

    public void MarkExpiryNoticeSent(int daysLeft) => LastExpiryNoticeDaysLeft = daysLeft;

    public SoftwareClientToken(
        Guid id,
        Guid tenantId,
        Guid projectId,
        Guid environmentId,
        string name,
        string tokenPrefix,
        string tokenHash,
        Guid? createdBy,
        DateTimeOffset createdAt,
        DateTimeOffset? expiresAt,
        string? note = null)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            throw new ArgumentException("Token name required.", nameof(name));
        }

        // Both set (an issued token) or both empty (a pending placeholder) — never one without the other.
        if (string.IsNullOrWhiteSpace(tokenPrefix) != string.IsNullOrWhiteSpace(tokenHash))
        {
            throw new ArgumentException("Token prefix and hash must be set together (or both empty for a pending token).");
        }

        Id = id;
        TenantId = tenantId;
        ProjectId = projectId;
        EnvironmentId = environmentId;
        Name = name.Trim();
        Note = note?.Trim() ?? string.Empty;
        TokenPrefix = tokenPrefix;
        TokenHash = tokenHash;
        CreatedBy = createdBy;
        CreatedAt = createdAt;
        ExpiresAt = expiresAt;
    }

    /// <summary>Updates the (non-secret) name and note; does not touch the secret, scope or expiry.</summary>
    public void UpdateDetails(string name, string? note)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            throw new ArgumentException("Token name required.", nameof(name));
        }

        Name = name.Trim();
        Note = note?.Trim() ?? string.Empty;
    }

    /// <summary>
    /// Creates a pending placeholder: the token record exists (visible, nameable, deletable) but has no
    /// secret yet — its first value is minted later via <see cref="Rotate"/>. Until then it cannot
    /// authenticate, so a placeholder is not a credential.
    /// </summary>
    public static SoftwareClientToken CreatePending(
        Guid id, Guid tenantId, Guid projectId, Guid environmentId, string name, Guid? createdBy, DateTimeOffset createdAt) =>
        new(id, tenantId, projectId, environmentId, name, tokenPrefix: "", tokenHash: "", createdBy, createdAt, expiresAt: null);

    /// <summary>False while the token is a pending placeholder (no value minted yet).</summary>
    public bool HasSecret => TokenHash.Length > 0;

    /// <summary>A token can authenticate only with a minted secret, while neither revoked nor past expiry.</summary>
    public bool IsActive(DateTimeOffset now) =>
        HasSecret && RevokedAt is null && (ExpiresAt is null || ExpiresAt > now);

    public void Revoke(DateTimeOffset at) => RevokedAt ??= at;

    /// <summary>
    /// Undoes a revocation: the stored secret becomes valid again exactly as it was (the expiry is NOT
    /// extended — a token that expired in the meantime stays expired until it is rotated).
    /// </summary>
    public void Reactivate() => RevokedAt = null;

    /// <summary>
    /// Replaces the secret on this record (the previous token stops working immediately) — or mints the
    /// FIRST secret of a pending placeholder.
    /// </summary>
    public void Rotate(string newPrefix, string newHash, DateTimeOffset at, DateTimeOffset? expiresAt)
    {
        if (RevokedAt is not null)
        {
            throw new InvalidOperationException("Cannot rotate a revoked token.");
        }

        if (string.IsNullOrWhiteSpace(newPrefix) || string.IsNullOrWhiteSpace(newHash))
        {
            throw new ArgumentException("New token prefix and hash required.");
        }

        TokenPrefix = newPrefix;
        TokenHash = newHash;
        LastRotatedAt = at;
        // Rotation issues a fresh credential, so its validity window restarts too — otherwise rotating an
        // expired token would hand out a token that is dead on arrival.
        CreatedAt = at;
        ExpiresAt = expiresAt;
        LastExpiryNoticeDaysLeft = null; // a new validity window gets its own notification schedule
    }
}
