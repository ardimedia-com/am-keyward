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

    public void Rename(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            throw new ArgumentException("Project name required.", nameof(name));
        }

        Name = name.Trim();
    }

    public RuntimeEnvironment AddEnvironment(Guid id, EnvironmentName name, DateTimeOffset createdAt)
    {
        if (_environments.Any(e => string.Equals(e.Name.Value, name.Value, StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException($"Environment '{name}' already exists in project '{Name}'.");
        }

        // Appended at the end of the display order: creation from a default set yields 0..n-1 in set
        // order, a later manual add lands after the existing ones. Callers must have the environments
        // loaded (the aggregate is the source of the next sort order).
        var sortOrder = _environments.Count == 0 ? 0 : _environments.Max(e => e.SortOrder) + 1;
        var env = new RuntimeEnvironment(id, Id, TenantId, name, sortOrder, createdAt);
        _environments.Add(env);
        return env;
    }
}

/// <summary>
/// One entry of a tenant's default environment set — the environments every NEW project ("application")
/// starts with. Maintained under Administration; a tenant with no rows uses the built-in
/// <see cref="ValueObjects.EnvironmentName.DefaultSet"/> (and deleting all rows returns to it).
/// Existing projects are never touched — their environments live on the project itself.
/// </summary>
public sealed class TenantDefaultEnvironment
{
    public Guid Id { get; private set; }

    /// <summary>Owning tenant (drives the tenant query filter and SQL Server row-level security).</summary>
    public Guid TenantId { get; private set; }

    public EnvironmentName Name { get; private set; }

    /// <summary>Display position within the tenant's set (0-based). Environments are ordered by this
    /// everywhere in the UI — never alphabetically — so Development, Test, Production stay in that order.</summary>
    public int SortOrder { get; private set; }

    public DateTimeOffset CreatedAt { get; private set; }

    public TenantDefaultEnvironment(Guid id, Guid tenantId, EnvironmentName name, int sortOrder, DateTimeOffset createdAt)
    {
        Id = id;
        TenantId = tenantId;
        Name = name;
        SortOrder = sortOrder;
        CreatedAt = createdAt;
    }

    public void Rename(EnvironmentName name) => Name = name;
}

/// <summary>A first-class environment within a project (Development/Test/Production, configurable).</summary>
public sealed class RuntimeEnvironment
{
    public Guid Id { get; private set; }
    public Guid ProjectId { get; private set; }

    /// <summary>Denormalized owning tenant (drives the tenant query filter and SQL Server row-level security).</summary>
    public Guid TenantId { get; private set; }

    public EnvironmentName Name { get; private set; }

    /// <summary>Display position within the project (0-based). Environments are ordered by this
    /// everywhere in the UI — never alphabetically — so Development, Test, Production stay in that order.</summary>
    public int SortOrder { get; private set; }

    public DateTimeOffset CreatedAt { get; private set; }

    public void Rename(EnvironmentName name) => Name = name;

    public RuntimeEnvironment(Guid id, Guid projectId, Guid tenantId, EnvironmentName name, int sortOrder, DateTimeOffset createdAt)
    {
        Id = id;
        ProjectId = projectId;
        TenantId = tenantId;
        Name = name;
        SortOrder = sortOrder;
        CreatedAt = createdAt;
    }
}

/// <summary>
/// Aggregate root: a <see cref="SecretKey"/> within a project, holding one <see cref="SecretValue"/>
/// per environment. Invariant: one key per project. The key is the client-facing lookup name and can be
/// renamed (<see cref="Rename"/>) without touching the values — identity is the ID, not the key.
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

    /// <summary>
    /// Renames the key. Safe for the stored values: the envelope AAD binds the secret's ID (not its key),
    /// so every existing version stays decryptable. Deployed software reading by key must follow, though —
    /// that is a caller/UI concern, not an invariant of this aggregate.
    /// </summary>
    public void Rename(SecretKey key) => Key = key;

    /// <summary>Sets (or adds a new version of) this secret's value for a given environment.</summary>
    public SecretValue SetValue(Guid valueId, Guid environmentId, Guid versionId, EncryptedValue encrypted, DateTimeOffset at)
    {
        var existing = EnsureValue(valueId, environmentId);
        existing.AddVersion(versionId, encrypted, at);
        return existing;
    }

    /// <summary>
    /// Returns this secret's value row for an environment, creating an EMPTY one (no version yet) if there
    /// is none. That empty row is what carries the rotation metadata — expiry date and note — before a value
    /// has ever been set, which is exactly when the note ("how do I obtain this value?") is most useful.
    /// Everything reading a value already treats "no current version" as "no value", so an empty row is
    /// indistinguishable from an absent one for readers.
    /// </summary>
    public SecretValue EnsureValue(Guid valueId, Guid environmentId)
    {
        var existing = _values.FirstOrDefault(v => v.EnvironmentId == environmentId);
        if (existing is not null)
        {
            return existing;
        }

        var created = new SecretValue(valueId, TenantId, Id, environmentId);
        _values.Add(created);
        return created;
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

    /// <summary>
    /// When this value is due for rotation (null = no date set). Unlike an app token's expiry this is purely
    /// ADVISORY: it never blocks a read. A forgotten renewal must not take a deployed application down — it
    /// raises a notice on the <see cref="Application.ExpiryNoticePolicy"/> schedule instead.
    /// </summary>
    public DateTimeOffset? ExpiresAt { get; private set; }

    /// <summary>
    /// Free-text rotation note for this value — typically how a new one is obtained (which portal, which
    /// command, who to ask). Empty when unset. It travels into the expiry notice, because that is the moment
    /// somebody needs it.
    /// </summary>
    public string Note { get; private set; } = string.Empty;

    /// <summary>
    /// Days-left bucket of the last expiry notice sent for the CURRENT value (dedupe state, mirrors
    /// <see cref="SoftwareClientToken.LastExpiryNoticeDaysLeft"/>). Reset whenever a new version is stored or
    /// the date changes — a fresh value gets a fresh notification schedule.
    /// </summary>
    public int? LastExpiryNoticeDaysLeft { get; private set; }

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
        // A new value is a completed rotation: the notices already sent applied to the value it replaced.
        LastExpiryNoticeDaysLeft = null;
        return version;
    }

    /// <summary>
    /// Sets the rotation metadata (expiry date and note; either may be null/empty to clear it). Changing the
    /// date restarts the notice schedule, so moving an expiry further out cannot leave a stale "10 days left"
    /// mark that suppresses the notices for the new window.
    /// </summary>
    public void SetRotationMetadata(DateTimeOffset? expiresAt, string? note)
    {
        if (expiresAt != ExpiresAt)
        {
            LastExpiryNoticeDaysLeft = null;
        }

        ExpiresAt = expiresAt;
        Note = note?.Trim() ?? string.Empty;
    }

    /// <summary>Records that an expiry notice was sent for this days-left bucket (dedupe).</summary>
    public void MarkExpiryNoticeSent(int daysLeft) => LastExpiryNoticeDaysLeft = daysLeft;

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
