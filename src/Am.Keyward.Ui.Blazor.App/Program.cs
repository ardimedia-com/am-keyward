using System.Threading.RateLimiting;
using Am.Keyward.Api;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Infrastructure;
using Am.Keyward.Infrastructure.Persistence;
using Am.Keyward.Ui.Blazor.App;
using Am.Keyward.Ui.Blazor.App.Components;
using Am.Keyward.Ui.Blazor.App.Identity;
using Microsoft.AspNetCore.Components.Server.Circuits;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;

const string managementPolicy = "Keyward.Management";

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// Demo-only: every circuit operates inside the seeded demo tenant (sign-in identifies the user, not the tenant yet).
builder.Services.AddScoped<CircuitHandler, DemoTenantCircuitHandler>();

// AM KEYWARD (standalone reference shell): SQL Server + a dev KEK loaded from a local key file outside
// the database. A real deployment supplies the connection string and a proper KEK provider.
var connectionString = builder.Configuration.GetConnectionString("Keyward")
    ?? "Server=localhost;Database=amkeyward;Integrated Security=True;Encrypt=False";
var (kek, kekId) = DevKek.LoadOrCreate(builder.Environment.ContentRootPath);
builder.Services.AddKeyward(connectionString, kek, kekId);

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
        var partitionKey = httpContext.Request.Headers.Authorization.ToString();
        if (string.IsNullOrEmpty(partitionKey))
        {
            partitionKey = httpContext.Connection.RemoteIpAddress?.ToString() ?? "anonymous";
        }

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

var app = builder.Build();

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
    .AddInteractiveServerRenderMode();

app.MapKeywardApi(authorizationPolicy: managementPolicy);  // management API: signed-in admin (cookie)
app.MapKeywardClientApi();                                  // software-client read API: token + rate limited

// Sign out (POST so it cannot be triggered cross-site via a simple link).
app.MapPost("/account/logout", async (SignInManager<IdentityUser> signInManager) =>
{
    await signInManager.SignOutAsync();
    return Results.LocalRedirect("/");
}).DisableAntiforgery();

app.Run();
