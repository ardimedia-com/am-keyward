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

/// <summary>Lifecycle of a break-glass grant (dual-control emergency access to server-side material).</summary>
public enum BreakGlassStatus
{
    Pending,
    Approved,
    Rejected,
    Consumed,
    Expired,
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

    /// <summary>A secret value was handed out through an approved reveal request (not a UI open, which is <see cref="Read"/>).</summary>
    Reveal,
    RevealRequested,
    RevealApproved,
    RevealRejected,
}

/// <summary>
/// Which kind of principal performed an audited action. The actor's identity is the pseudonym; the kind tells
/// apart what the same user did in person from what a token acting for them did.
/// </summary>
public enum ActorKind
{
    /// <summary>A signed-in human.</summary>
    User,

    /// <summary>A deployed application presenting a software-client token.</summary>
    SoftwareClient,

    /// <summary>An AI agent presenting an agent token that acts for its issuing user.</summary>
    Agent,

    /// <summary>No principal: seeding, background jobs, maintenance.</summary>
    System,
}
