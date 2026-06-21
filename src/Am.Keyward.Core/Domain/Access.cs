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
    public Guid Id { get; private set; }
    public Guid? TenantId { get; private set; }
    public PrincipalType PrincipalType { get; private set; }
    public Guid PrincipalId { get; private set; }
    public GrantScope Scope { get; private set; }
    public Permission Permission { get; private set; }
    public Guid? CreatedBy { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }

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
