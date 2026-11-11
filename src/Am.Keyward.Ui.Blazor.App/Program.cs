using Am.Keyward.Api;
using Am.Keyward.AspNetCore;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Identity;
using Am.Keyward.Infrastructure;
using Am.Keyward.Infrastructure.Persistence;
using Am.Keyward.Infrastructure.Monitoring;
using Am.Keyward.Ui.Blazor;
using Am.Keyward.Ui.Blazor.App;
using Am.Keyward.Ui.Blazor.App.Components;
using Am.Keyward.Ui.Blazor.App.Hosting;
using Am.Keyward.Ui.Blazor.App.Identity;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Localization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

const string managementPolicy = "Keyward.Management";
const string systemAdminPolicy = "Keyward.SystemAdmin";
string[] supportedCultures = ["en", "de", "fr", "it", "es", "pt"];

var builder = WebApplication.CreateBuilder(args);

// Machine-local overrides (e.g. the SMTP relay host, local secrets) — gitignored, never committed, optional
// so a machine without it still runs. The one hand-added config file we allow (see follow-framework-conventions.md).
builder.Configuration.AddJsonFile("appsettings.Local.json", optional: true, reloadOnChange: true);

// The startup checks run before the container exists, so they log through a bootstrap logger (console + debug,
// filtered by the same Logging section) — a refused start must say why.
using var bootstrapLoggerFactory = LoggerFactory.Create(logging => logging
    .AddConfiguration(builder.Configuration.GetSection("Logging"))
    .AddSimpleConsole()
    .AddDebug());
var bootstrapLogger = bootstrapLoggerFactory.CreateLogger("Am.Keyward.Ui.Blazor.App.Startup");

// Refuse to start on a configuration that would fail silently and dangerously: no explicit environment, no
// connection string or public base URL outside Development, an unknown registration mode, a malformed proxy list,
// no usable key custody. Nothing below touches the database, the key or the mail relay before this passed.
var isDevelopment = builder.Environment.IsDevelopment();
var startupErrors = ShellStartupValidation
    .Validate(builder.Configuration, ShellStartupValidation.ExplicitEnvironment(builder.Configuration), isDevelopment)
    .ToList();
ShellKekResult? kek = null;
if (startupErrors.Count == 0)
{
    (kek, var kekError) = ShellKek.Load(builder.Configuration, builder.Environment.ContentRootPath, isDevelopment, bootstrapLogger);
    if (kekError is not null)
    {
        startupErrors.Add(kekError);
    }
}

if (startupErrors.Count > 0 || kek is null)
{
    foreach (var error in startupErrors)
    {
        bootstrapLogger.LogCritical("AM KEYWARD refuses to start: {Reason}", error);
    }

    Environment.ExitCode = 1;
    return;
}

builder.Services.AddRazorComponents()
    // Hold a disconnected circuit longer so a short network drop / device sleep returns to a live session
    // instead of a full reload (server memory cost is negligible for this low-concurrency admin UI).
    .AddInteractiveServerComponents(options =>
    {
        options.DisconnectedCircuitRetentionPeriod = TimeSpan.FromMinutes(30);
        // Development only: surface the full circuit exception in the browser console instead of the
        // generic "unhandled exception on the current circuit" message. Never enabled in production —
        // stack traces can leak internals.
        options.DetailedErrors = isDevelopment;
    });

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

// UI localization (English default, German, French, Italian, Spanish, Portuguese). The Keyward strings live in the
// RCL's SharedResource, the shell's own in Resources/ShellResource.*.resx.
builder.Services.AddLocalization(options => options.ResourcesPath = "Resources");
builder.Services.Configure<RequestLocalizationOptions>(options =>
{
    options.SetDefaultCulture("en").AddSupportedCultures(supportedCultures).AddSupportedUICultures(supportedCultures);
});

// Per-circuit scope: the reusable Keyward user handler establishes the current user from the circuit's auth
// state — sign-in identifies the user, not the tenant.
builder.Services.AddKeywardBlazorUserScope();

// The shell is a SINGLE-ORGANIZATION host (one tenant), so it takes the packaged single-tenant glue
// instead of hand-writing it: this registers the workspace context the embedded UI pages read AND the
// circuit handler that pins the tenant. The HTTP/SSR half is app.UseKeywardSingleTenant below. A
// multi-tenant host does not use this — it implements IKeywardWorkspaceContext from its own selection.
builder.Services.AddKeywardSingleTenant(Demo.TenantId);
// The product name users see (browser tab, sidebar brand, texts) and the public base URL for absolute
// links in account and notification e-mails — the host names its installation.
builder.Services.AddKeywardUi(o =>
{
    o.ProductName = builder.Configuration["Keyward:ProductName"] ?? o.ProductName;
    o.PublicBaseUrl = builder.Configuration[ShellStartupValidation.PublicBaseUrlKey];
    o.NotificationLanguage = builder.Configuration["Keyward:NotificationLanguage"];
});

// AM KEYWARD (standalone reference shell): SQL Server + the KEK chosen by ShellKek (Development: local dev key
// file; elsewhere: DPAPI-protected key file outside the deploy folder). Only Development has a connection-string
// fallback — the startup validation refused anything else without one.
var connectionString = builder.Configuration.GetConnectionString(ShellStartupValidation.ConnectionStringName)
    ?? "Server=localhost;Database=amkeyward;Integrated Security=True;Encrypt=False";
builder.Services.AddKeyward(connectionString, kek.Key, kek.KekId);

// Break-glass: the non-repudiable, append-only trail lives outside the database. Outside Development the library
// refuses to start without a path, so default it NEXT TO the KEK file: outside the deploy folder, same custody.
// A real deployment may point SinkFilePath at storage the database admin cannot rewrite; an explicit setting wins.
builder.Services.Configure<Am.Keyward.Infrastructure.Auth.BreakGlassOptions>(
    builder.Configuration.GetSection(Am.Keyward.Infrastructure.Auth.BreakGlassOptions.SectionName));
if (!builder.Environment.IsDevelopment())
{
    var breakGlassDirectory = builder.Configuration[ShellKek.DirectoryKey] is { Length: > 0 } configuredKekDirectory
        ? configuredKekDirectory
        : ShellKek.DefaultDirectory;
    builder.Services.PostConfigure<Am.Keyward.Infrastructure.Auth.BreakGlassOptions>(o =>
    {
        if (string.IsNullOrWhiteSpace(o.SinkFilePath))
        {
            o.SinkFilePath = Path.Combine(breakGlassDirectory, "breakglass-audit.jsonl");
        }
    });
}

// --- ASP.NET Core Identity (shell-owned; the libraries stay identity-agnostic) ---
builder.Services.AddDbContext<KeywardIdentityDbContext>(options =>
    options.UseSqlServer(connectionString, sql =>
        sql.MigrationsHistoryTable("__EFMigrationsHistory", KeywardIdentityDbContext.Schema)));

builder.Services.AddCascadingAuthenticationState();
// Re-validates the user of a live circuit (deleted / disabled / security stamp changed) every 10 minutes.
builder.Services.AddScoped<AuthenticationStateProvider, IdentityRevalidatingAuthenticationStateProvider>();
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

// Account links (confirmation, reset, invitation) are built from Keyward:PublicBaseUrl, never the request host.
builder.Services.AddScoped<AccountLinkBuilder>();

// Self-registration: InviteOnly (default) or Open (demo only). Invitations are single-use, short-lived links.
builder.Services.Configure<RegistrationOptions>(builder.Configuration.GetSection(RegistrationOptions.SectionName));
var registrationOptions = builder.Configuration.GetSection(RegistrationOptions.SectionName).Get<RegistrationOptions>()
    ?? new RegistrationOptions();
builder.Services.Configure<InvitationTokenProviderOptions>(o =>
    o.TokenLifespan = TimeSpan.FromHours(Math.Clamp(registrationOptions.InvitationLifetimeHours, 1, 24 * 14)));
builder.Services.AddScoped<RegistrationGate>();
builder.Services.AddScoped<InvitationService>();
builder.Services.AddScoped<AdminUserDeletion>();

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
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    })
    .AddEntityFrameworkStores<KeywardIdentityDbContext>()
    .AddSignInManager()
    .AddDefaultTokenProviders()
    .AddTokenProvider<InvitationTokenProvider>(InvitationTokenProvider.ProviderName);

// The session cookie: 8 h sliding, HttpOnly, HTTPS only, SameSite=Lax (antiforgery protects every form post; Lax
// keeps deep links from e-mails and bookmarks working). Persistence stays opt-in ("Remember me" unchecked).
builder.Services.ConfigureApplicationCookie(options =>
{
    options.ExpireTimeSpan = TimeSpan.FromHours(8);
    options.SlidingExpiration = true;
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.LoginPath = "/Account/Login";
    options.AccessDeniedPath = "/account/access-denied";
});
// A disabled, deleted or reset account loses its cookie session within 5 minutes (security stamp re-check).
builder.Services.Configure<SecurityStampValidatorOptions>(options => options.ValidationInterval = TimeSpan.FromMinutes(5));

// Software-client token authentication + per-token rate limiting (read API). The library registers the
// Keyward.SoftwareClient scheme, its authorization policy AND the per-token rate-limiter policy, so the host
// only adds the middleware (app.UseRateLimiter, below). Pass a lambda to AddKeywardSoftwareClientApi to tune
// the limits. AllowedNetworks narrows each API to the networks its callers live in (CIDR list, checked before any
// token lookup; others get 403). Unset, the client API is open to every network (a startup warning says so).
builder.Services.AddKeywardSoftwareClientApi(o =>
    o.AllowedNetworks = builder.Configuration[KeywardSoftwareClientApiOptions.AllowedNetworksConfigurationKey]);
builder.Services.AddKeywardAgentApi(o =>         // Keyward.Agent scheme + per-token rate limiter
    o.AllowedNetworks = builder.Configuration[KeywardAgentApiOptions.AllowedNetworksConfigurationKey]);

// The agent API is mapped only on purpose: Keyward:Agent:Enabled = true, or an AllowedNetworks list for it.
const string agentApiEnabledKey = "Keyward:Agent:Enabled";
var agentApiEnabled = builder.Configuration.GetValue<bool>(agentApiEnabledKey)
    || !string.IsNullOrWhiteSpace(builder.Configuration[KeywardAgentApiOptions.AllowedNetworksConfigurationKey]);

// Per-IP throttling of the anonymous account form posts (sign-in, registration, password reset, invitation).
builder.Services.AddKeywardAccountRateLimiting(builder.Configuration);

// Behind a reverse proxy: trust X-Forwarded-For/-Proto from the configured proxies only (off when none is set).
var forwardedHeadersEnabled = ShellForwardedHeaders.IsEnabled(builder.Configuration);
if (forwardedHeadersEnabled)
{
    builder.Services.Configure<ForwardedHeadersOptions>(o => ShellForwardedHeaders.Configure(o, builder.Configuration));
}

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

// Renders and mails the alerts that AddKeyward's notification poller collects — access-pattern alerts from
// the statistics flush (a token used from a never-seen IP, active again after a long silence), the heartbeat
// monitor's missed/recovered deadlines and the token/secret expiry notices. The poller itself lives in
// Am.Keyward.Infrastructure so that an embedded Keyward gets it too; this is the shell's branded-mail
// implementation of the port.
builder.Services.AddScoped<IKeywardAlertPresenter, Am.Keyward.Ui.Blazor.App.Identity.BrandedMailAlertPresenter>();

// Monitoring/health: a live KEK-availability probe and the cached ops-monitor snapshot (KEK integrity,
// audit-chain integrity, token expiry) and the single-instance check (one running instance per database is the
// supported deployment). Exposed at /health (liveness) and /health/ready (readiness).
builder.Services.AddHealthChecks()
    .AddCheck<KekAvailabilityHealthCheck>("kek-availability", tags: ["ready", "live"])
    .AddCheck<OpsMonitorHealthCheck>("ops-monitor", tags: ["ready"])
    .AddCheck<KeywardSingleInstanceHealthCheck>("single-instance", tags: ["ready"]);

var app = builder.Build();

LogStartupPosture(app, kek, registrationOptions.Mode, agentApiEnabled, forwardedHeadersEnabled, dataProtectionWarning);

// Apply migrations (both contexts), ensure the shell's tenant, and seed the demo project (Development, or
// Keyward:SeedDemo = true).
await using (var scope = app.Services.CreateAsyncScope())
{
    var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
    await db.Database.MigrateAsync();
    await scope.ServiceProvider.GetRequiredService<KeywardIdentityDbContext>().Database.MigrateAsync();

    // Seed inside the tenant scope: row-level security must see the tenant for the existence check
    // (otherwise it re-seeds every start) and must admit the seed rows (the BLOCK predicates
    // require SESSION_CONTEXT('TenantId') to equal the rows' tenant).
    scope.ServiceProvider.GetRequiredService<ITenantScopeSetter>().SetTenant(Demo.TenantId);
    await Demo.EnsureSeededAsync(db, seedDemoProject: app.Configuration.GetValue<bool?>(Demo.SeedDemoKey) ?? isDevelopment);
}

// Configure the HTTP request pipeline. Forwarded headers first, so everything after (HTTPS redirection, the rate
// limiter, the network allow-lists, the audit) sees the real client.
if (forwardedHeadersEnabled)
{
    app.UseForwardedHeaders();
}

// Security headers on every response, including error and status-code pages.
app.UseKeywardSecurityHeaders();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseRequestLocalization();
app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);
app.UseHttpsRedirection();

// Before authentication: the software-client token is validated inside the authorization middleware, and the
// account forms must be throttled before any credential check — so the limiter rejects first.
app.UseRateLimiter();

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

// Single-organization host: pin the tenant on the HTTP/SSR path too. The circuit handler from
// AddKeywardSingleTenant only covers the interactive path, and a PRERENDERING Keyward page calls a Keyward
// service before the circuit exists — without this it would hit an unset ambient tenant.
app.UseKeywardSingleTenant(Demo.TenantId);

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode()
    // Discover the routable feature pages that live in the Am.Keyward.Ui.Blazor RCL (endpoint routing in
    // the Blazor Web App model scans the App assembly by default; RCL pages must be added explicitly).
    .AddAdditionalAssemblies(typeof(Am.Keyward.Ui.Blazor.Pages.Applications).Assembly);

app.MapKeywardApi(authorizationPolicy: managementPolicy);  // management API: signed-in admin (cookie)
app.MapKeywardClientApi();                                  // software-client read API: token + rate limited
if (agentApiEnabled)
{
    app.MapKeywardAgentApi();                               // agent API (/keyward/api/v1/agent): agent token + rate limited
}

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

// Sign out: a POST with a valid antiforgery token, so another site can neither link nor auto-submit it.
app.MapPost("/account/logout", async (HttpContext ctx, IAntiforgery antiforgery, SignInManager<IdentityUser> signInManager) =>
{
    if (!await antiforgery.IsRequestValidAsync(ctx))
    {
        return Results.BadRequest();
    }

    await signInManager.SignOutAsync();
    return Results.LocalRedirect("/");
});

// Per-user notification preferences: e-mail when app tokens near expiry, on token access alerts, and from
// heartbeat monitoring (antiforgery-protected form post from the profile page; an unchecked checkbox
// posts no value).
app.MapPost("/account/profile/notify", async (HttpContext ctx, [FromForm] string? notify, [FromForm] string? notifyAccess,
    [FromForm] string? notifyMonitoring, UserManager<IdentityUser> users, KeywardDbContext db) =>
{
    var identityId = users.GetUserId(ctx.User);
    if (identityId is null)
    {
        return Results.Unauthorized();
    }

    var appUser = await db.Users.FirstOrDefaultAsync(u => u.Issuer == null && u.ExternalId == identityId);
    if (appUser is not null)
    {
        appUser.SetExpiryNotification(notify == "true");
        appUser.SetTokenAccessAlertNotification(notifyAccess == "true");
        appUser.SetMonitoringNotification(notifyMonitoring == "true");
        await db.SaveChangesAsync();
    }

    return Results.LocalRedirect("/account/profile?saved=1");
}).RequireAuthorization();

// Admin user-management actions (system-admin only): unlock a brute-force lockout, or disable / re-enable an
// account. Antiforgery-protected form posts (the admin page renders the token). Every action is audited.
var adminUsers = app.MapGroup("/account/admin/users").RequireAuthorization(systemAdminPolicy);

// Invite a user by e-mail (the InviteOnly onboarding; also works in Open mode). Creates the account pending and
// mails a single-use set-password link; for a still-pending invitation it re-issues the link (the old one dies).
adminUsers.MapPost("/invite", async (HttpContext ctx, [FromForm] string? email,
    InvitationService invitations, UserManager<IdentityUser> users, KeywardDbContext db, IAuditSink audit) =>
{
    var outcome = await invitations.InviteAsync(email, ctx.RequestAborted);
    if (outcome != InvitationOutcome.Sent)
    {
        return Results.LocalRedirect($"/account/admin/users?inviteError={outcome}");
    }

    var invited = email!.Trim();
    if (await users.FindByEmailAsync(invited) is { } user)
    {
        await AuditUserAdminAsync(ctx, db, audit, user.Id, "invite");
    }

    return Results.LocalRedirect($"/account/admin/users?invited={Uri.EscapeDataString(invited)}");
});

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
    UserManager<IdentityUser> users, KeywardDbContext db, IAuditSink audit, [FromServices] IKeywardIdentityBinder keywardUsers) =>
{
    // Never let an admin disable their own account (self-lockout).
    if (userId != users.GetUserId(ctx.User))
    {
        var user = await users.FindByIdAsync(userId);
        if (user is not null)
        {
            await users.SetLockoutEnabledAsync(user, true);
            await users.SetLockoutEndDateAsync(user, DateTimeOffset.MaxValue);
            // The lockout only stops a NEW sign-in: rotating the security stamp ends the running sessions too
            // (cookie re-validation and the circuit's revalidating auth-state provider both compare it).
            await users.UpdateSecurityStampAsync(user);
            // The lockout only stops sign-in; Keyward must know too, so nothing keeps acting for the user.
            await keywardUsers.DisableAsync(userId);
            await AuditUserAdminAsync(ctx, db, audit, userId, "disable");
        }
    }

    return Results.LocalRedirect("/account/admin/users");
});

adminUsers.MapPost("/enable", async (HttpContext ctx, [FromForm] string userId,
    UserManager<IdentityUser> users, KeywardDbContext db, IAuditSink audit, [FromServices] IKeywardIdentityBinder keywardUsers) =>
{
    var user = await users.FindByIdAsync(userId);
    if (user is not null)
    {
        await users.SetLockoutEndDateAsync(user, null);
        await users.ResetAccessFailedCountAsync(user);
        await keywardUsers.EnableAsync(userId);
        await AuditUserAdminAsync(ctx, db, audit, userId, "enable");
    }

    return Results.LocalRedirect("/account/admin/users");
});

// Delete an account (offboarding) with the personal-vault retention: see AdminUserDeletion. Guards: never self, never
// the last tenant admin, never the last system admin. The admin's action is audited before anything changes.
adminUsers.MapPost("/delete", async (HttpContext ctx, [FromForm] string userId,
    UserManager<IdentityUser> users, KeywardDbContext db, IAuditSink audit, AdminUserDeletion deletion) =>
{
    await deletion.DeleteAsync(
        userId, users.GetUserId(ctx.User), Demo.TenantId,
        () => AuditUserAdminAsync(ctx, db, audit, userId, "delete"),
        ctx.RequestAborted);

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
// Antiforgery-protected (the top-bar form renders the token); only supported cultures, only local redirects.
app.MapPost("/culture", async (HttpContext context, IAntiforgery antiforgery) =>
{
    if (!context.Request.HasFormContentType || !await antiforgery.IsRequestValidAsync(context))
    {
        return Results.BadRequest();
    }

    var form = await context.Request.ReadFormAsync(context.RequestAborted);
    var culture = form["culture"].ToString();
    if (supportedCultures.Contains(culture, StringComparer.OrdinalIgnoreCase))
    {
        context.Response.Cookies.Append(
            CookieRequestCultureProvider.DefaultCookieName,
            CookieRequestCultureProvider.MakeCookieValue(new RequestCulture(culture)),
            new CookieOptions
            {
                Expires = DateTimeOffset.UtcNow.AddYears(1),
                IsEssential = true,
                Path = "/",
                HttpOnly = true,
                Secure = context.Request.IsHttps,
                SameSite = SameSiteMode.Lax,
            });
    }

    return Results.LocalRedirect(LocalUrl.OrRoot(form["redirectUri"].ToString()));
});

app.Run();

// One block of startup facts an operator needs to see once: where the key lives, how accounts come in, what is
// exposed, and the supported topology.
static void LogStartupPosture(WebApplication app, ShellKekResult kek, RegistrationMode registration,
    bool agentApiEnabled, bool forwardedHeadersEnabled, string? dataProtectionWarning)
{
    var logger = app.Logger;
    if (dataProtectionWarning is not null)
    {
        logger.LogWarning(
            "Data Protection key-ring persistence unavailable, using the framework default store (users may be signed out on restart): {Reason}",
            dataProtectionWarning);
    }

    if (kek.Created)
    {
        logger.LogWarning(
            "A new key-encryption key {KekId} was created at {KekPath}. Back it up offline now (escrow export): losing it makes every stored secret unreadable.",
            kek.KekId, kek.Location);
    }
    else
    {
        logger.LogInformation("Key-encryption key {KekId} loaded from {KekPath}.", kek.KekId, kek.Location);
    }

    if (registration == RegistrationMode.Open)
    {
        logger.LogWarning(
            "Self-registration is Open: anyone who can reach this site can create an account and becomes a tenant member. Use it for demos only; set Keyward:Registration:Mode to InviteOnly otherwise.");
    }

    if (!agentApiEnabled)
    {
        logger.LogInformation(
            "The agent API is not mapped. Set Keyward:Agent:Enabled = true or Keyward:Agent:AllowedNetworks to expose it.");
    }

    if (!app.Environment.IsDevelopment())
    {
        if (string.Equals(app.Configuration["AllowedHosts"], "*", StringComparison.Ordinal))
        {
            logger.LogWarning("AllowedHosts is '*'. Restrict it to the host name(s) this installation is reached at.");
        }

        if (!forwardedHeadersEnabled)
        {
            logger.LogInformation(
                "No reverse proxy configured (Keyward:ForwardedHeaders:KnownProxies / KnownNetworks). Behind a proxy every caller would carry the proxy's address.");
        }
    }

    logger.LogInformation(
        "AM KEYWARD supports one running instance per database: background jobs (notifications, statistics, migrations) are not coordinated across instances.");
}

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
