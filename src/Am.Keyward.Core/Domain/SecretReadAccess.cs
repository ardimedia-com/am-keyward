namespace Am.Keyward.Core.Domain.Software;

/// <summary>How a software secret's value was read.</summary>
public enum SecretReadSource
{
    /// <summary>Read in-process through <c>ISoftwareSecretService</c> — an embedding host's own code.</summary>
    InProcess = 0,

    /// <summary>Read by a deployed application through the software-client API (token authenticated).</summary>
    Client = 1,
}

/// <summary>
/// Read statistics for one software secret in one environment — a single upserted row (last read at/via +
/// total count), not a row per read. Written batched by the access-statistics flush, so the secret-read hot
/// path never pays for it. Like the token statistics tables it is installation-global (written by a
/// background job outside any tenant scope, deliberately no tenant query filter / row-level security);
/// reads always filter through the secret's project. Unlike the token counters it is NEVER trimmed by
/// retention: "when was this key last read" is exactly the long-term signal ("is this secret still
/// used?"), and one row per (secret, environment) cannot grow. Management reads (the UI's data tab) are
/// deliberately not counted — only software consumption (client API and in-process reads) is.
/// </summary>
public sealed class SecretReadAccess
{
    public Guid Id { get; private set; }
    public Guid TenantId { get; private set; }
    public Guid SoftwareSecretId { get; private set; }

    /// <summary>
    /// The environment the value was read in. Deliberately no foreign key: a cascade from
    /// <see cref="RuntimeEnvironment"/> would open a second cascade path (both reach the project), which
    /// SQL Server rejects — environment deletion removes these rows explicitly instead.
    /// </summary>
    public Guid EnvironmentId { get; private set; }

    public DateTimeOffset LastReadAt { get; private set; }
    public SecretReadSource LastReadSource { get; private set; }
    public long ReadCount { get; private set; }

    public SecretReadAccess(
        Guid id, Guid tenantId, Guid softwareSecretId, Guid environmentId,
        DateTimeOffset lastReadAt, SecretReadSource lastReadSource, long readCount)
    {
        Id = id;
        TenantId = tenantId;
        SoftwareSecretId = softwareSecretId;
        EnvironmentId = environmentId;
        LastReadAt = lastReadAt;
        LastReadSource = lastReadSource;
        ReadCount = readCount;
    }

    public void RecordRead(DateTimeOffset at, SecretReadSource source, long count)
    {
        LastReadAt = at;
        LastReadSource = source;
        ReadCount += count;
    }
}
