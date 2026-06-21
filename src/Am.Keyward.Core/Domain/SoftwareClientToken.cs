namespace Am.Keyward.Core.Domain.Software;

/// <summary>
/// A credential a deployed piece of software presents (as a Bearer token) to read its own secrets. It is
/// scoped to exactly one (project, environment) so a leaked token cannot read another environment. Only a
/// hash of the token is stored — the plaintext is shown once, at issuance; <see cref="TokenPrefix"/> is a
/// non-secret lookup handle. Tokens expire, can be rotated (new secret on the same record) and revoked.
/// The record carries <see cref="TenantId"/> so that, once authenticated, the request runs in the token's
/// tenant scope; the table itself is installation-global (looked up before the tenant is known).
/// </summary>
public sealed class SoftwareClientToken
{
    public Guid Id { get; private set; }
    public Guid TenantId { get; private set; }
    public Guid ProjectId { get; private set; }
    public Guid EnvironmentId { get; private set; }
    public string Name { get; private set; }

    /// <summary>Non-secret, indexed lookup handle (the leading segment of the token).</summary>
    public string TokenPrefix { get; private set; }

    /// <summary>SHA-256 (hex) of the full token string. The plaintext token is never stored.</summary>
    public string TokenHash { get; private set; }

    public Guid? CreatedBy { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }
    public DateTimeOffset? ExpiresAt { get; private set; }
    public DateTimeOffset? LastRotatedAt { get; private set; }
    public DateTimeOffset? RevokedAt { get; private set; }

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
        DateTimeOffset? expiresAt)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            throw new ArgumentException("Token name required.", nameof(name));
        }

        if (string.IsNullOrWhiteSpace(tokenPrefix))
        {
            throw new ArgumentException("Token prefix required.", nameof(tokenPrefix));
        }

        if (string.IsNullOrWhiteSpace(tokenHash))
        {
            throw new ArgumentException("Token hash required.", nameof(tokenHash));
        }

        Id = id;
        TenantId = tenantId;
        ProjectId = projectId;
        EnvironmentId = environmentId;
        Name = name.Trim();
        TokenPrefix = tokenPrefix;
        TokenHash = tokenHash;
        CreatedBy = createdBy;
        CreatedAt = createdAt;
        ExpiresAt = expiresAt;
    }

    /// <summary>A token can authenticate only while it is neither revoked nor past its expiry.</summary>
    public bool IsActive(DateTimeOffset now) =>
        RevokedAt is null && (ExpiresAt is null || ExpiresAt > now);

    public void Revoke(DateTimeOffset at) => RevokedAt ??= at;

    /// <summary>Replaces the secret on this record (the previous token stops working immediately).</summary>
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
        ExpiresAt = expiresAt;
    }
}
