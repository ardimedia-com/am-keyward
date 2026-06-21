using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Am.Keyward.Ui.Blazor.App.Identity;

/// <summary>
/// ASP.NET Core Identity store for the standalone reference shell. Identity is the SHELL's concern (the
/// Keyward libraries stay identity-agnostic and consume a <c>ClaimsPrincipal</c> / <c>ICurrentUser</c>),
/// so its tables live in their own <see cref="Schema"/>, separate from the domain tables in <c>amkeyward</c>.
/// </summary>
public sealed class KeywardIdentityDbContext(DbContextOptions<KeywardIdentityDbContext> options)
    : IdentityDbContext<IdentityUser>(options)
{
    public const string Schema = "amkeyward_identity";

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.HasDefaultSchema(Schema);
    }
}
