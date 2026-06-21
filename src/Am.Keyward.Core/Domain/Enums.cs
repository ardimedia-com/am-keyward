namespace Am.Keyward.Core.Domain;

/// <summary>Who owns a vault or project. Personal vaults are owned by a <see cref="User"/> and are tenant-less.</summary>
public enum OwnerType
{
    Tenant,
    Group,
    User,
}

/// <summary>Per-vault encryption model. Software projects are always <see cref="ServerSide"/>.</summary>
public enum ProtectionMode
{
    ServerSide,
    ZeroKnowledge,
}

/// <summary>What an access grant allows the principal to do.</summary>
public enum Permission
{
    Read,
    Write,
    Manage,
}

/// <summary>The kind of principal an access grant is given to.</summary>
public enum PrincipalType
{
    User,
    Group,
}

/// <summary>A user's role within a tenant (carried by a tenant membership).</summary>
public enum TenantRole
{
    Member,
    TenantAdmin,
}

/// <summary>A user's role within a group (carried by a group membership).</summary>
public enum GroupRole
{
    Member,
    Admin,
}

/// <summary>The shape of a human-vault item.</summary>
public enum ItemType
{
    Login,
    SecureNote,
    ApiCredential,
    ConnectionString,
    Generic,
}

/// <summary>What an access grant is scoped to.</summary>
public enum GrantScopeKind
{
    Vault,
    Project,
    Environment,
}

/// <summary>The audited operation.</summary>
public enum AuditAction
{
    Create,
    Read,
    Update,
    Delete,
    Grant,
    Revoke,
    Login,
    BreakGlass,
}
