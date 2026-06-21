using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.ValueObjects;

namespace Am.Keyward.Core.Domain.Software;

/// <summary>
/// Aggregate root for software credentials. Owned by a Tenant or Group (never a User) and always
/// server-side. Contains its <see cref="RuntimeEnvironment"/>s.
/// </summary>
public sealed class Project
{
    private readonly List<RuntimeEnvironment> _environments = [];

    public Guid Id { get; private set; }
    public Guid TenantId { get; private set; }
    public OwnerType OwnerType { get; private set; }
    public Guid OwnerId { get; private set; }
    public string Name { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }
    public IReadOnlyList<RuntimeEnvironment> Environments => _environments;

    public Project(Guid id, Guid tenantId, OwnerType ownerType, Guid ownerId, string name, DateTimeOffset createdAt)
    {
        if (ownerType == OwnerType.User)
        {
            throw new ArgumentException("A software project must be owned by a Tenant or Group, not a User.", nameof(ownerType));
        }

        if (string.IsNullOrWhiteSpace(name))
        {
            throw new ArgumentException("Project name required.", nameof(name));
        }

        Id = id;
        TenantId = tenantId;
        OwnerType = ownerType;
        OwnerId = ownerId;
        Name = name.Trim();
        CreatedAt = createdAt;
    }

    public RuntimeEnvironment AddEnvironment(Guid id, EnvironmentName name, DateTimeOffset createdAt)
    {
        if (_environments.Any(e => string.Equals(e.Name.Value, name.Value, StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException($"Environment '{name}' already exists in project '{Name}'.");
        }

        var env = new RuntimeEnvironment(id, Id, TenantId, name, createdAt);
        _environments.Add(env);
        return env;
    }
}

/// <summary>A first-class environment within a project (Development/Test/Preview/Production, configurable).</summary>
public sealed class RuntimeEnvironment
{
    public Guid Id { get; private set; }
    public Guid ProjectId { get; private set; }

    /// <summary>Denormalized owning tenant (drives the tenant query filter and SQL Server row-level security).</summary>
    public Guid TenantId { get; private set; }

    public EnvironmentName Name { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }

    public RuntimeEnvironment(Guid id, Guid projectId, Guid tenantId, EnvironmentName name, DateTimeOffset createdAt)
    {
        Id = id;
        ProjectId = projectId;
        TenantId = tenantId;
        Name = name;
        CreatedAt = createdAt;
    }
}

/// <summary>
/// Aggregate root: a stable <see cref="SecretKey"/> within a project, holding one
/// <see cref="SecretValue"/> per environment. Invariant: one key per project.
/// </summary>
public sealed class SoftwareSecret
{
    private readonly List<SecretValue> _values = [];

    public Guid Id { get; private set; }
    public Guid ProjectId { get; private set; }

    /// <summary>Denormalized owning tenant (drives the tenant query filter and SQL Server row-level security).</summary>
    public Guid TenantId { get; private set; }

    public SecretKey Key { get; private set; }

    /// <summary>Steward (the user who created/manages it); tombstoned (set null) on user deletion.</summary>
    public Guid? CreatedBy { get; private set; }

    public DateTimeOffset CreatedAt { get; private set; }
    public IReadOnlyList<SecretValue> Values => _values;

    public SoftwareSecret(Guid id, Guid projectId, Guid tenantId, SecretKey key, Guid? createdBy, DateTimeOffset createdAt)
    {
        Id = id;
        ProjectId = projectId;
        TenantId = tenantId;
        Key = key;
        CreatedBy = createdBy;
        CreatedAt = createdAt;
    }

    /// <summary>Sets (or adds a new version of) this secret's value for a given environment.</summary>
    public SecretValue SetValue(Guid valueId, Guid environmentId, Guid versionId, EncryptedValue encrypted, DateTimeOffset at)
    {
        var existing = _values.FirstOrDefault(v => v.EnvironmentId == environmentId);
        if (existing is null)
        {
            var created = new SecretValue(valueId, TenantId, Id, environmentId);
            created.AddVersion(versionId, encrypted, at);
            _values.Add(created);
            return created;
        }

        existing.AddVersion(versionId, encrypted, at);
        return existing;
    }
}

/// <summary>One environment's value of a software secret; owns the version chain. Envelope lives on the version.</summary>
public sealed class SecretValue
{
    private readonly List<SecretVersion> _versions = [];

    public Guid Id { get; private set; }

    /// <summary>Denormalized owning tenant (drives the tenant query filter and SQL Server row-level security).</summary>
    public Guid TenantId { get; private set; }

    public Guid SoftwareSecretId { get; private set; }
    public Guid EnvironmentId { get; private set; }
    public Guid? CurrentVersionId { get; private set; }
    public IReadOnlyList<SecretVersion> Versions => _versions;

    public SecretValue(Guid id, Guid tenantId, Guid softwareSecretId, Guid environmentId)
    {
        Id = id;
        TenantId = tenantId;
        SoftwareSecretId = softwareSecretId;
        EnvironmentId = environmentId;
    }

    public SecretVersion AddVersion(Guid versionId, EncryptedValue encrypted, DateTimeOffset at)
    {
        var version = new SecretVersion(versionId, TenantId, Id, _versions.Count + 1, encrypted, at);
        _versions.Add(version);
        CurrentVersionId = version.Id;
        return version;
    }

    /// <summary>Resolves the current version via the pointer (never by max timestamp).</summary>
    public SecretVersion Current =>
        _versions.SingleOrDefault(v => v.Id == CurrentVersionId)
        ?? throw new InvalidOperationException("Secret value has no current version.");
}

/// <summary>An immutable, encrypted version of a secret value.</summary>
public sealed class SecretVersion
{
    public Guid Id { get; private set; }

    /// <summary>Denormalized owning tenant (drives the tenant query filter and SQL Server row-level security).</summary>
    public Guid TenantId { get; private set; }

    public Guid SecretValueId { get; private set; }
    public int VersionNumber { get; private set; }
    public EncryptedValue Encrypted { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }

    public SecretVersion(Guid id, Guid tenantId, Guid secretValueId, int versionNumber, EncryptedValue encrypted, DateTimeOffset createdAt)
    {
        Id = id;
        TenantId = tenantId;
        SecretValueId = secretValueId;
        VersionNumber = versionNumber;
        Encrypted = encrypted;
        CreatedAt = createdAt;
    }
}
