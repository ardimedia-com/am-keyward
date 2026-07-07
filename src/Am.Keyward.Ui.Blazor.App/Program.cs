using Am.Keyward.Api;
using Am.Keyward.AspNetCore;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Identity;
using Am.Keyward.Infrastructure;
using Am.Keyward.Infrastructure.Persistence;
using Am.Keyward.Infrastructure.Monitoring;
using Am.Keyward.Ui.Blazor;
using Am.Keyward.Ui.Blazor.App;
using Am.Keyward.Ui.Blazor.App.Components;
using Am.Keyward.Ui.Blazor.App.Identity;
using Microsoft.AspNetCore.Components.Server.Circuits;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Localization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

const string managementPolicy = "Keyward.Management";
const string systemAdminPolicy = "Keyward.SystemAdmin";

var builder = WebApplication.CreateBuilder(args);

// Machine-local overrides (e.g. the SMTP relay host, local secrets) — gitignored, never committed, optional
// so a machine without it still runs. The one hand-added config file we allow (see follow-framework-conventions.md).
builder.Configuration.AddJsonFile("appsettings.Local.json", optional: true, reloadOnChange: true);

builder.Services.AddRazorComponents()
    // Hold a disconnected circuit longer so a short network drop / device sleep returns to a live session
    // instead of a full reload (server memory cost is negligible for this low-concurrency admin UI).
    .AddInteractiveServerComponents(options =>
        options.DisconnectedCircuitRetentionPeriod = TimeSpan.FromMinutes(30));

// Persist the Data Protection key ring to a stable location OUTSIDE the deploy folder, so an app restart
// or redeploy does not regenerate the keys and sign every user out (and break outstanding Identity reset /
// confirmation tokens). Best-effort: fall back to SetApplicationName alone if the shared folder is not
// writable, so a locked-down host still starts. DPAPI at-rest protection is Windows-only (this reference
// shell is Windows). See auth-policy-and-session-implementation.md (Part 2, Data Protection).
var dataProtection = builder.Services.AddDataProtection().SetApplicationName("Am.Keyward");
string? dataProtectionWarning = null;
try
{
    var keyRingPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Ardimedia", "Am.Keyward", "keys");
    Directory.CreateDirectory(keyRingPath);
    dataProtection.PersistKeysToFileSystem(new DirectoryInfo(keyRingPath));
    if (OperatingSystem.IsWindows())
    {
        dataProtection.ProtectKeysWithDpapi(protectToLocalMachine: true);
    }
}
catch (Exception ex)
{
    // Fall back to the default key store (SetApplicationName still applied). Logged after Build(), below.
    dataProtectionWarning = ex.Message;
}

// UI localization (English default, German). Strings live in Resources/SharedResource.*.resx.
builder.Services.AddLocalization(options => options.ResourcesPath = "Resources");
builder.Services.Configure<RequestLocalizationOptions>(options =>
{
    string[] cultures = ["en", "de", "fr", "it", "es", "pt"];
    options.SetDefaultCulture("en").AddSupportedCultures(cultures).AddSupportedUICultures(cultures);
});

// Per-circuit scope: the reusable Keyward user handler establishes the current user from the circuit's auth
// state; the demo tenant handler pins the (demo-only) tenant — sign-in identifies the user, not the tenant yet.
builder.Services.AddKeywardBlazorUserScope();
builder.Services.AddScoped<CircuitHandler, DemoTenantCircuitHandler>();

// The workspace context the embedded Keyward UI pages (RCL) read for their tenant. The reference shell
// points it at the demo tenant; a real host supplies its own selection. AddKeywardUi registers the RCL's
// own circuit-scoped UI state (e.g. the application picked on the Applications page).
builder.Services.AddScoped<Am.Keyward.Ui.Blazor.IKeywardWorkspaceContext, DemoWorkspaceContext>();
// The product name users see (browser tab, sidebar brand, texts) and the public base URL for absolute
// links in notification e-mails — the host names its installation.
builder.Services.AddKeywardUi(o =>
{
    o.ProductName = builder.Configuration["Keyward:ProductName"] ?? o.ProductName;
    o.PublicBaseUrl = builder.Configuration["Keyward:PublicBaseUrl"];
});

// AM KEYWARD (standalone reference shell): SQL Server + a dev KEK loaded from a local key file outside
// the database. A real deployment supplies the connection string and a proper KEK provider.
var connectionString = builder.Configuration.GetConnectionString("Keyward")
    ?? "Server=localhost;Database=amkeyward;Integrated Security=True;Encrypt=False";
var (kek, kekId) = DevKek.LoadOrCreate(builder.Environment.ContentRootPath);
builder.Services.AddKeyward(connectionString, kek, kekId);

// Break-glass: the non-repudiable, append-only trail lives outside the database. A real deployment points
// SinkFilePath at storage the database admin cannot rewrite (separate host / restricted permissions).
builder.Services.Configure<Am.Keyward.Infrastructure.Auth.BreakGlassOptions>(
    builder.Configuration.GetSection(Am.Keyward.Infrastructure.Auth.BreakGlassOptions.SectionName));

// --- ASP.NET Core Identity (shell-owned; the libraries stay identity-agnostic) ---
builder.Services.AddDbContext<KeywardIdentityDbContext>(options =>
    options.UseSqlServer(connectionString, sql =>
        sql.MigrationsHistoryTable("__EFMigrationsHistory", KeywardIdentityDbContext.Schema)));

builder.Services.AddCascadingAuthenticationState();
builder.Services.AddHttpContextAccessor();

// Account e-mail delivery (password-reset link). The reference shell drops mails to a local folder; a real
// deployment replaces IAccountEmailSender with an SMTP sender.
builder.Services.Configure<AccountEmailOptions>(builder.Configuration.GetSection(AccountEmailOptions.SectionName));
// Send over SMTP when a relay host is configured (e.g. appsettings.Local.json -> smtptest.ardimedia.com);
// otherwise drop the mail to a local file. See smtp-relay-hosts.md for the relay host per LAN/environment.
if (!string.IsNullOrWhiteSpace(builder.Configuration[$"{AccountEmailOptions.SectionName}:Smtp:Host"]))
{
    builder.Services.AddScoped<IAccountEmailSender, SmtpAccountEmailSender>();
}
else
{
    builder.Services.AddScoped<IAccountEmailSender, MaildropAccountEmailSender>();
}
builder.Services.AddScoped<IUserClaimsPrincipalFactory<IdentityUser>, KeywardUserClaimsPrincipalFactory>();
builder.Services.AddAuthentication(IdentityConstants.ApplicationScheme).AddIdentityCookies();
builder.Services.AddIdentityCore<IdentityUser>(options =>
    {
        options.User.RequireUniqueEmail = true;
        // Require a confirmed e-mail before sign-in. Registration then never reveals whether an address is
        // already taken (it always shows "check your e-mail"), and an unconfirmed self-signup can't sign in.
        options.SignIn.RequireConfirmedAccount = true;
        // Password policy: a strong minimum length matters more than mandatory symbols (a long passphrase
        // beats forced punctuation). See auth-policy-and-session-implementation.md (Part 1).
        options.Password.RequiredLength = 12;
        options.Password.RequireDigit = true;
        options.Password.RequireLowercase = true;
        options.Password.RequireUppercase = true;
        options.Password.RequireNonAlphanumeric = false;
        options.Lockout.AllowedForNewUsers = true;
        options.Lockout.MaxFailedAccessAttempts = 5;
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    })
    .AddEntityFrameworkStores<KeywardIdentityDbContext>()
    .AddSignInManager()
    .AddDefaultTokenProviders();

// Software-client token authentication + per-token rate limiting (read API). The library registers the
// Keyward.SoftwareClient scheme, its authorization policy AND the per-token rate-limiter policy, so the host
// only adds the middleware (app.UseRateLimiter, below). Pass a lambda to AddKeywardSoftwareClientApi to tune
// the limits.
builder.Services.AddKeywardSoftwareClientApi();

// The management API requires a signed-in admin (cookie scheme); the system-admin policy additionally
// requires the Keyward system-admin claim (used to gate the admin user-management UI + endpoints).
builder.Services.AddAuthorizationBuilder()
    .AddPolicy(managementPolicy, policy =>
    {
        policy.AddAuthenticationSchemes(IdentityConstants.ApplicationScheme);
        policy.RequireAuthenticatedUser();
    })
    .AddPolicy(systemAdminPolicy, policy =>
    {
        policy.AddAuthenticationSchemes(IdentityConstants.ApplicationScheme);
        policy.RequireClaim(KeywardClaims.SystemAdmin, "true");
    });

// Runtime migration safety-net (covers the DB being swapped under the running app).
builder.Services.Configure<DatabaseMigrationOptions>(builder.Configuration.GetSection(DatabaseMigrationOptions.SectionName));
builder.Services.AddHostedService<Am.Keyward.Ui.Blazor.App.BackgroundServices.DatabaseMigrationBackgroundService>();

// E-mails administrators (who opted in on their profile) about app tokens nearing expiry:
// 30/20/10 days ahead, then daily from 9 days (TokenExpiryNoticePolicy).
builder.Services.AddHostedService<Am.Keyward.Ui.Blazor.App.BackgroundServices.TokenExpiryEmailService>();

// Monitoring/health: a live KEK-availability probe and the cached ops-monitor snapshot (KEK integrity,
// audit-chain integrity, token expiry). Exposed at /health (liveness) and /health/ready (readiness).
builder.Services.AddHealthChecks()
    .AddCheck<KekAvailabilityHealthCheck>("kek-availability", tags: ["ready", "live"])
    .AddCheck<OpsMonitorHealthCheck>("ops-monitor", tags: ["ready"]);

var app = builder.Build();

if (dataProtectionWarning is not null)
{
    app.Logger.LogWarning(
        "Data Protection key-ring persistence unavailable, using the framework default store (users may be signed out on restart): {Reason}",
        dataProtectionWarning);
}

// Apply migrations (both contexts) and seed the demo tenant/project (dev convenience).
await using (var scope = app.Services.CreateAsyncScope())
{
    var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
    await db.Database.MigrateAsync();
    await scope.ServiceProvider.GetRequiredService<KeywardIdentityDbContext>().Database.MigrateAsync();

    // Seed inside the demo tenant scope: row-level security must see the demo tenant for the existence
    // check (otherwise it re-seeds every start) and must admit the seed rows (the BLOCK predicates
    // require SESSION_CONTEXT('TenantId') to equal the rows' tenant).
    scope.ServiceProvider.GetRequiredService<ITenantScopeSetter>().SetTenant(Demo.TenantId);
    await Demo.EnsureSeededAsync(db);
}

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseRequestLocalization();
app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);
app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

// MUST come after UseAuthentication/UseAuthorization: antiforgery tokens are bound to the current
// claims-based user. Running it earlier binds every token to the anonymous user, and the first form
// POST on an AUTHENTICATED page then fails with "token was meant for a different claims-based user"
// (anonymous account pages — login/register — never trip it, which is why it went unnoticed).
app.UseAntiforgery();

// Establish the server-authoritative current user from the authenticated principal for this request (HTTP
// path; the Blazor circuit path is covered by AddKeywardBlazorUserScope's circuit handler).
app.UseKeywardCurrentUser();

app.UseRateLimiter();

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode()
    // Discover the routable feature pages that live in the Am.Keyward.Ui.Blazor RCL (endpoint routing in
    // the Blazor Web App model scans the App assembly by default; RCL pages must be added explicitly).
    .AddAdditionalAssemblies(typeof(Am.Keyward.Ui.Blazor.Pages.Secrets).Assembly);

app.MapKeywardApi(authorizationPolicy: managementPolicy);  // management API: signed-in admin (cookie)
app.MapKeywardClientApi();                                  // software-client read API: token + rate limited

// Health endpoints: liveness (KEK reachable) and readiness (KEK + ops-monitor snapshot). Anonymous and
// body-free by default so they leak nothing; operators put detail behind their own auth if needed.
app.MapHealthChecks("/health", new Microsoft.AspNetCore.Diagnostics.HealthChecks.HealthCheckOptions
{
    Predicate = check => check.Tags.Contains("live"),
});
app.MapHealthChecks("/health/ready", new Microsoft.AspNetCore.Diagnostics.HealthChecks.HealthCheckOptions
{
    Predicate = check => check.Tags.Contains("ready"),
});

// Sign out (POST so it cannot be triggered cross-site via a simple link).
app.MapPost("/account/logout", async (SignInManager<IdentityUser> signInManager) =>
{
    await signInManager.SignOutAsync();
    return Results.LocalRedirect("/");
}).DisableAntiforgery();

// Per-user notification preference: e-mail when app tokens near expiry (antiforgery-protected form post
// from the profile page; an unchecked checkbox posts no value).
app.MapPost("/account/profile/notify", async (HttpContext ctx, [FromForm] string? notify,
    UserManager<IdentityUser> users, KeywardDbContext db) =>
{
    var identityId = users.GetUserId(ctx.User);
    if (identityId is null)
    {
        return Results.Unauthorized();
    }

    var appUser = await db.Users.FirstOrDefaultAsync(u => u.Issuer == null && u.ExternalId == identityId);
    if (appUser is not null)
    {
        appUser.SetTokenExpiryNotification(notify == "true");
        await db.SaveChangesAsync();
    }

    return Results.LocalRedirect("/account/profile?saved=1");
}).RequireAuthorization();

// Admin user-management actions (system-admin only): unlock a brute-force lockout, or disable / re-enable an
// account. Antiforgery-protected form posts (the admin page renders the token). Every action is audited.
var adminUsers = app.MapGroup("/account/admin/users").RequireAuthorization(systemAdminPolicy);

adminUsers.MapPost("/unlock", async (HttpContext ctx, [FromForm] string userId,
    UserManager<IdentityUser> users, KeywardDbContext db, IAuditSink audit) =>
{
    var user = await users.FindByIdAsync(userId);
    if (user is not null)
    {
        await users.SetLockoutEndDateAsync(user, null);
        await users.ResetAccessFailedCountAsync(user);
        await AuditUserAdminAsync(ctx, db, audit, userId, "unlock");
    }

    return Results.LocalRedirect("/account/admin/users");
});

adminUsers.MapPost("/disable", async (HttpContext ctx, [FromForm] string userId,
    UserManager<IdentityUser> users, KeywardDbContext db, IAuditSink audit) =>
{
    // Never let an admin disable their own account (self-lockout).
    if (userId != users.GetUserId(ctx.User))
    {
        var user = await users.FindByIdAsync(userId);
        if (user is not null)
        {
            await users.SetLockoutEnabledAsync(user, true);
            await users.SetLockoutEndDateAsync(user, DateTimeOffset.MaxValue);
            await AuditUserAdminAsync(ctx, db, audit, userId, "disable");
        }
    }

    return Results.LocalRedirect("/account/admin/users");
});

adminUsers.MapPost("/enable", async (HttpContext ctx, [FromForm] string userId,
    UserManager<IdentityUser> users, KeywardDbContext db, IAuditSink audit) =>
{
    var user = await users.FindByIdAsync(userId);
    if (user is not null)
    {
        await users.SetLockoutEndDateAsync(user, null);
        await users.ResetAccessFailedCountAsync(user);
        await AuditUserAdminAsync(ctx, db, audit, userId, "enable");
    }

    return Results.LocalRedirect("/account/admin/users");
});

// Delete an account (offboarding): removes the Identity login, the tenant membership(s), the user's access
// grants and their personal vaults (folders/items/versions cascade). The domain AppUser row is kept so the
// audit chain's actor references stay meaningful. Guards: never self, never the last tenant admin, never
// the last system admin. The vault deletion runs in the TARGET user's scope — the row-level-security
// predicate admits personal vaults only for their owner, so an admin delete must act on the owner's behalf.
adminUsers.MapPost("/delete", async (HttpContext ctx, [FromForm] string userId,
    UserManager<IdentityUser> users, KeywardDbContext db, IAuditSink audit,
    IUserScopeSetter userScope, ITenantScopeSetter tenantScope) =>
{
    if (userId == users.GetUserId(ctx.User))
    {
        return Results.LocalRedirect("/account/admin/users");
    }

    var domainUser = await db.Users.FirstOrDefaultAsync(u => u.Issuer == null && u.ExternalId == userId);
    if (domainUser is not null)
    {
        var isLastSystemAdmin = domainUser.IsSystemAdmin
            && await db.Users.CountAsync(u => u.IsSystemAdmin) <= 1;
        var isLastTenantAdmin = await db.TenantMemberships.AnyAsync(m =>
                m.TenantId == Demo.TenantId && m.UserId == domainUser.Id && m.Role == TenantRole.TenantAdmin)
            && await db.TenantMemberships.CountAsync(m =>
                m.TenantId == Demo.TenantId && m.Role == TenantRole.TenantAdmin) <= 1;
        if (isLastSystemAdmin || isLastTenantAdmin)
        {
            return Results.LocalRedirect("/account/admin/users");
        }

        // Audit FIRST (as the acting admin), then switch to the target's scope for the data removal.
        await AuditUserAdminAsync(ctx, db, audit, userId, "delete");

        userScope.SetUser(domainUser.Id);
        tenantScope.SetTenant(Demo.TenantId);

        var vaultIds = await db.Vaults
            .Where(v => v.TenantId == null && v.OwnerUserId == domainUser.Id)
            .Select(v => v.Id)
            .ToListAsync();
        db.AccessGrants.RemoveRange(await db.AccessGrants
            .Where(g => (g.Scope.Kind == GrantScopeKind.Vault && vaultIds.Contains(g.Scope.TargetId))
                || (g.PrincipalType == PrincipalType.User && g.PrincipalId == domainUser.Id))
            .ToListAsync());
        db.Vaults.RemoveRange(await db.Vaults
            .Where(v => v.TenantId == null && v.OwnerUserId == domainUser.Id)
            .ToListAsync());
        db.TenantMemberships.RemoveRange(await db.TenantMemberships
            .Where(m => m.UserId == domainUser.Id)
            .ToListAsync());
        await db.SaveChangesAsync();
    }

    var identityUser = await users.FindByIdAsync(userId);
    if (identityUser is not null)
    {
        await users.DeleteAsync(identityUser);
    }

    return Results.LocalRedirect("/account/admin/users");
});

// Assign the demo-tenant role (Member / TenantAdmin). Creates the membership when the user has none yet
// (e.g. not signed in since memberships were introduced). Server-side guard: the LAST tenant admin can
// never be demoted, so the tenant always keeps one.
adminUsers.MapPost("/role", async (HttpContext ctx, [FromForm] string userId, [FromForm] string role,
    KeywardDbContext db, IAuditSink audit, IClock clock) =>
{
    if (Enum.TryParse<TenantRole>(role, out var newRole))
    {
        var domainUser = await db.Users.FirstOrDefaultAsync(u => u.Issuer == null && u.ExternalId == userId);
        if (domainUser is not null)
        {
            var membership = await db.TenantMemberships
                .FirstOrDefaultAsync(m => m.TenantId == Demo.TenantId && m.UserId == domainUser.Id);

            var isLastAdmin = membership?.Role == TenantRole.TenantAdmin
                && await db.TenantMemberships.CountAsync(m =>
                    m.TenantId == Demo.TenantId && m.Role == TenantRole.TenantAdmin) <= 1;

            if (!(newRole == TenantRole.Member && isLastAdmin))
            {
                if (membership is null)
                {
                    db.TenantMemberships.Add(new TenantMembership(Guid.NewGuid(), Demo.TenantId, domainUser.Id, newRole, clock.UtcNow));
                }
                else
                {
                    membership.ChangeRole(newRole);
                }

                await db.SaveChangesAsync();
                await AuditUserAdminAsync(ctx, db, audit, userId, $"role:{newRole}");
            }
        }
    }

    return Results.LocalRedirect("/account/admin/users");
});

// Switch UI language: store the culture cookie and reload (the cookie applies on the next request).
app.MapPost("/culture", (HttpContext context) =>
{
    var culture = context.Request.Form["culture"].ToString();
    var redirectUri = context.Request.Form["redirectUri"].ToString();
    if (!string.IsNullOrWhiteSpace(culture))
    {
        context.Response.Cookies.Append(
            CookieRequestCultureProvider.DefaultCookieName,
            CookieRequestCultureProvider.MakeCookieValue(new RequestCulture(culture)),
            new CookieOptions { Expires = DateTimeOffset.UtcNow.AddYears(1), IsEssential = true, Path = "/" });
    }

    return Results.LocalRedirect(string.IsNullOrWhiteSpace(redirectUri) ? "/" : redirectUri);
}).DisableAntiforgery();

app.Run();

// Audit an admin user-management action to the installation-global (null-tenant) audit chain, attributed to
// the acting admin, targeting the affected user. disable -> Revoke (access removed); unlock/enable -> Grant.
static async Task AuditUserAdminAsync(HttpContext ctx, KeywardDbContext db, IAuditSink audit, string targetIdentityUserId, string action)
{
    var actorId = Guid.TryParse(ctx.User.FindFirst(KeywardClaims.UserId)?.Value, out var a) ? a : (Guid?)null;
    var targetAppUserId = await db.Users
        .Where(u => u.Issuer == null && u.ExternalId == targetIdentityUserId)
        .Select(u => (Guid?)u.Id)
        .FirstOrDefaultAsync();

    var auditAction = action switch
    {
        "disable" => AuditAction.Revoke,
        "delete" => AuditAction.Delete,
        _ => AuditAction.Grant,
    };
    await audit.AppendAsync(new AuditRequest(null, auditAction, "AppUser", targetAppUserId, actorId));
    await db.SaveChangesAsync();
}
