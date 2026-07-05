using System.Security.Cryptography;
using System.Text;
using System.Threading.RateLimiting;
using Am.Keyward.Api;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Infrastructure;
using Am.Keyward.Infrastructure.Persistence;
using Am.Keyward.Infrastructure.Monitoring;
using Am.Keyward.Ui.Blazor.App;
using Am.Keyward.Ui.Blazor.App.Components;
using Am.Keyward.Ui.Blazor.App.Identity;
using Microsoft.AspNetCore.Components.Server.Circuits;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Localization;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;

const string managementPolicy = "Keyward.Management";

var builder = WebApplication.CreateBuilder(args);

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

// Demo-only: every circuit operates inside the seeded demo tenant (sign-in identifies the user, not the tenant yet).
builder.Services.AddScoped<CircuitHandler, DemoTenantCircuitHandler>();

// The workspace context the embedded Keyward UI pages (RCL) read for their tenant/project. The reference
// shell points it at the demo tenant/project; a real host supplies its own selection.
builder.Services.AddScoped<Am.Keyward.Ui.Blazor.IKeywardWorkspaceContext, DemoWorkspaceContext>();

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
builder.Services.AddScoped<IUserClaimsPrincipalFactory<IdentityUser>, KeywardUserClaimsPrincipalFactory>();
builder.Services.AddAuthentication(IdentityConstants.ApplicationScheme).AddIdentityCookies();
builder.Services.AddIdentityCore<IdentityUser>(options =>
    {
        options.User.RequireUniqueEmail = true;
        options.SignIn.RequireConfirmedAccount = false;
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

// Software-client token authentication + per-token rate limiting (read API).
builder.Services.AddKeywardSoftwareClientApi();
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy(KeywardClientApi.RateLimiterPolicy, httpContext =>
    {
        // Partition per token, but never hold the plaintext bearer token as the (in-memory) key: hash it,
        // so a leaked limiter dump reveals no secrets and the key is fixed-width regardless of token length.
        var authHeader = httpContext.Request.Headers.Authorization.ToString();
        var partitionKey = string.IsNullOrEmpty(authHeader)
            ? "ip:" + (httpContext.Connection.RemoteIpAddress?.ToString() ?? "anonymous")
            : "tok:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(authHeader)));

        return RateLimitPartition.GetFixedWindowLimiter(partitionKey, _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 60,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
        });
    });
});

// The management API requires a signed-in admin (cookie scheme).
builder.Services.AddAuthorizationBuilder()
    .AddPolicy(managementPolicy, policy =>
    {
        policy.AddAuthenticationSchemes(IdentityConstants.ApplicationScheme);
        policy.RequireAuthenticatedUser();
    });

// Runtime migration safety-net (covers the DB being swapped under the running app).
builder.Services.Configure<DatabaseMigrationOptions>(builder.Configuration.GetSection(DatabaseMigrationOptions.SectionName));
builder.Services.AddHostedService<Am.Keyward.Ui.Blazor.App.BackgroundServices.DatabaseMigrationBackgroundService>();

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
app.UseAntiforgery();

app.UseAuthentication();
app.UseAuthorization();

// Establish the server-authoritative current user from the authenticated principal for this request
// (HTTP path; the Blazor circuit sets it from its authentication state — see DemoTenantCircuitHandler).
app.Use(async (context, next) =>
{
    if (Guid.TryParse(context.User.FindFirst(KeywardUserClaimsPrincipalFactory.UserIdClaim)?.Value, out var userId))
    {
        context.RequestServices.GetRequiredService<IUserScopeSetter>().SetUser(userId);
    }

    await next();
});

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
