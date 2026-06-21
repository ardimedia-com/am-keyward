using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.ValueObjects;

namespace Am.Keyward.Core.Domain.Access;

/// <summary>
/// Grants a principal (user or group) a permission on a scoped resource (vault / project / environment).
/// Cross-tenant grants are forbidden in v0.1; <see cref="TenantId"/> is null only for a grant on a
/// tenant-less personal vault.
/// </summary>
public sealed class AccessGrant
{
    public Guid Id { get; }
    public Guid? TenantId { get; }
    public PrincipalType PrincipalType { get; }
    public Guid PrincipalId { get; }
    public GrantScope Scope { get; }
    public Permission Permission { get; private set; }
    public Guid? CreatedBy { get; }
    public DateTimeOffset CreatedAt { get; }

    public AccessGrant(Guid id, Guid? tenantId, PrincipalType principalType, Guid principalId, GrantScope scope, Permission permission, Guid? createdBy, DateTimeOffset createdAt)
    {
        Id = id;
        TenantId = tenantId;
        PrincipalType = principalType;
        PrincipalId = principalId;
        Scope = scope;
        Permission = permission;
        CreatedBy = createdBy;
        CreatedAt = createdAt;
    }

    public void ChangePermission(Permission permission) => Permission = permission;
}
