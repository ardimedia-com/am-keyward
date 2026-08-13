namespace Am.Keyward.Core.Abstractions;

/// <summary>
/// The active workspace the embedded Keyward UI operates in: the tenant whose organization-owned resources
/// are shown. The <b>host</b> supplies this from its own tenant selection (so a host can scope the embedded
/// pages to whatever the signed-in user picked); the standalone reference shell returns its seeded demo
/// tenant. The current user/actor and the personal (tenant-less) scope come from <see cref="ICurrentUser"/>
/// instead, so this only carries the org context. The software application ("project") is NOT part of this
/// contract — the UI's own Applications page selects it.
/// <para>
/// A single-organization host does not implement this itself: <c>AddKeywardSingleTenant</c>
/// (<c>Am.Keyward.AspNetCore</c>) registers a fixed-tenant implementation together with the matching scope
/// handlers.
/// </para>
/// </summary>
public interface IKeywardWorkspaceContext
{
    /// <summary>The active tenant (organization) whose team vaults / software credentials are shown.</summary>
    Guid TenantId { get; }
}

/// <summary>
/// What the HOST has decided a signed-in user may be in Keyward, expressed in Keyward's own terms. The host
/// derives it from whatever access model it has (ASP.NET Identity roles, group membership, an OIDC claim);
/// <see cref="IKeywardIdentityBinder"/> then makes Keyward's own records match. This is the whole contract of
/// "the host decides, Keyward enforces" — Keyward never reads the host's roles.
/// </summary>
/// <param name="IsSystemAdmin">Installation-wide administrator (implies tenant administration).</param>
/// <param name="IsSoftwareManager">May manage the software side: applications, machine secrets, client tokens.</param>
/// <param name="IsTenantMember">May use the tenant's vaults. <c>false</c> REVOKES an existing membership.</param>
public readonly record struct KeywardIdentityBinding(bool IsSystemAdmin, bool IsSoftwareManager, bool IsTenantMember)
{
    /// <summary>The common "this user administers everything" binding.</summary>
    public static KeywardIdentityBinding Administrator { get; } = new(true, true, true);

    /// <summary>The common "ordinary user with vaults" binding.</summary>
    public static KeywardIdentityBinding Member { get; } = new(false, false, true);

    /// <summary>Nothing at all — the user gets no Keyward identity and any tenant membership is removed.</summary>
    public static KeywardIdentityBinding None { get; } = new(false, false, false);

    /// <summary>Whether this binding grants anything; a host can skip binding entirely when it does not.</summary>
    public bool GrantsAnything => this.IsSystemAdmin || this.IsSoftwareManager || this.IsTenantMember;
}

/// <summary>The Keyward user a host identity was bound to.</summary>
/// <param name="UserId">The Keyward <c>AppUser</c> id — what the host stamps as the user-id claim.</param>
/// <param name="IsSystemAdmin">The effective flag after binding, for the system-admin claim.</param>
public readonly record struct KeywardBoundUser(Guid UserId, bool IsSystemAdmin);

/// <summary>
/// Maps a host identity onto Keyward's own user and membership records: finds or just-in-time creates the
/// <c>AppUser</c> for an external id, keeps its flags in sync with the host's decision, and reconciles the
/// tenant membership (including REMOVING it when the host withdrew vault access).
/// <para>
/// This exists so every embedding host stops re-implementing the same ~150 lines of just-in-time user
/// creation, app-lock serialization and membership reconciliation. The host keeps only the part that is
/// genuinely its own: translating its access model into a <see cref="KeywardIdentityBinding"/>. In ASP.NET
/// Core that is a <c>UserClaimsPrincipalFactory</c> plus one call to
/// <c>KeywardClaimsBinding.ApplyAsync</c> (<c>Am.Keyward.AspNetCore</c>).
/// </para>
/// <para>
/// Registered by <c>AddKeyward</c>. It touches the Keyward database, so callers on an authentication path
/// MUST treat a failure as non-fatal — see the helper above, which does.
/// </para>
/// </summary>
public interface IKeywardIdentityBinder
{
    /// <summary>
    /// Binds one host identity. <paramref name="externalId"/> is the host's own stable user id (the value
    /// that identifies this user forever — an ASP.NET Identity user id, an OIDC subject); it is the key the
    /// <c>AppUser</c> is looked up by, so it must never change for a given person.
    /// </summary>
    /// <param name="externalId">The host's stable user id.</param>
    /// <param name="displayName">Shown in Keyward's UI (user name / e-mail); only used when creating.</param>
    /// <param name="tenantId">The tenant whose membership is reconciled.</param>
    /// <param name="binding">What the host decided this user may be.</param>
    Task<KeywardBoundUser> BindAsync(
        string externalId,
        string displayName,
        Guid tenantId,
        KeywardIdentityBinding binding,
        CancellationToken cancellationToken = default);
}
