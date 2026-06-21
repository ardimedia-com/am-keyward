using Am.Keyward.Core.Domain;

namespace Am.Keyward.Core.Domain.Identity;

/// <summary>An isolation boundary. In company-wide (single-tenant) mode a single implicit "system" tenant exists.</summary>
public sealed class Tenant
{
    public Guid Id { get; }
    public string Name { get; private set; }
    public bool IsSystemTenant { get; }
    public DateTimeOffset CreatedAt { get; }

    public Tenant(Guid id, string name, bool isSystemTenant, DateTimeOffset createdAt)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            throw new ArgumentException("Tenant name required.", nameof(name));
        }

        Id = id;
        Name = name.Trim();
        IsSystemTenant = isSystemTenant;
        CreatedAt = createdAt;
    }

    public void Rename(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            throw new ArgumentException("Tenant name required.", nameof(name));
        }

        Name = name.Trim();
    }
}

/// <summary>A global, installation-level account. Not owned by a tenant; may belong to 0..n tenants.</summary>
public sealed class AppUser
{
    public Guid Id { get; }

    /// <summary>External IdP issuer in embedded mode; null for the standalone Identity store.</summary>
    public string? Issuer { get; }

    /// <summary>The stable external claim (sub/oid) or the local Identity user id. Unique together with <see cref="Issuer"/>.</summary>
    public string ExternalId { get; }

    public string DisplayName { get; private set; }
    public bool IsSystemAdmin { get; private set; }
    public DateTimeOffset CreatedAt { get; }

    public AppUser(Guid id, string? issuer, string externalId, string displayName, bool isSystemAdmin, DateTimeOffset createdAt)
    {
        if (string.IsNullOrWhiteSpace(externalId))
        {
            throw new ArgumentException("ExternalId required.", nameof(externalId));
        }

        Id = id;
        Issuer = string.IsNullOrWhiteSpace(issuer) ? null : issuer.Trim();
        ExternalId = externalId.Trim();
        DisplayName = string.IsNullOrWhiteSpace(displayName) ? ExternalId : displayName.Trim();
        IsSystemAdmin = isSystemAdmin;
        CreatedAt = createdAt;
    }

    public void GrantSystemAdmin() => IsSystemAdmin = true;

    public void RevokeSystemAdmin() => IsSystemAdmin = false;
}

/// <summary>Many-to-many user↔tenant link with a per-tenant role (0..n tenants per user).</summary>
public sealed class TenantMembership
{
    public Guid Id { get; }
    public Guid TenantId { get; }
    public Guid UserId { get; }
    public TenantRole Role { get; private set; }
    public DateTimeOffset CreatedAt { get; }

    public TenantMembership(Guid id, Guid tenantId, Guid userId, TenantRole role, DateTimeOffset createdAt)
    {
        Id = id;
        TenantId = tenantId;
        UserId = userId;
        Role = role;
        CreatedAt = createdAt;
    }

    public void ChangeRole(TenantRole role) => Role = role;
}

/// <summary>A group within a tenant; can own vaults/projects and has one or more group admins.</summary>
public sealed class UserGroup
{
    public Guid Id { get; }
    public Guid TenantId { get; }
    public string Name { get; private set; }
    public DateTimeOffset CreatedAt { get; }

    public UserGroup(Guid id, Guid tenantId, string name, DateTimeOffset createdAt)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            throw new ArgumentException("Group name required.", nameof(name));
        }

        Id = id;
        TenantId = tenantId;
        Name = name.Trim();
        CreatedAt = createdAt;
    }

    public void Rename(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            throw new ArgumentException("Group name required.", nameof(name));
        }

        Name = name.Trim();
    }
}

/// <summary>Many-to-many user↔group link with a per-group role (Member|Admin; multiple admins allowed).</summary>
public sealed class GroupMembership
{
    public Guid Id { get; }
    public Guid GroupId { get; }
    public Guid UserId { get; }
    public GroupRole Role { get; private set; }
    public DateTimeOffset CreatedAt { get; }

    public GroupMembership(Guid id, Guid groupId, Guid userId, GroupRole role, DateTimeOffset createdAt)
    {
        Id = id;
        GroupId = groupId;
        UserId = userId;
        Role = role;
        CreatedAt = createdAt;
    }

    public void ChangeRole(GroupRole role) => Role = role;
}
