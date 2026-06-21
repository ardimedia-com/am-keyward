using System.Threading.RateLimiting;
using Am.Keyward.Api;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Infrastructure;
using Am.Keyward.Infrastructure.Persistence;
using Am.Keyward.Ui.Blazor.App;
using Am.Keyward.Ui.Blazor.App.Components;
using Microsoft.AspNetCore.Components.Server.Circuits;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// Demo-only: every circuit operates inside the seeded demo tenant until sign-in exists.
builder.Services.AddScoped<CircuitHandler, DemoTenantCircuitHandler>();

// AM KEYWARD (standalone reference shell): SQL Server + a dev KEK loaded from a local key file outside
// the database. A real deployment supplies the connection string and a proper KEK provider.
var connectionString = builder.Configuration.GetConnectionString("Keyward")
    ?? "Server=localhost;Database=amkeyward;Integrated Security=True;Encrypt=False";
var (kek, kekId) = DevKek.LoadOrCreate(builder.Environment.ContentRootPath);
builder.Services.AddKeyward(connectionString, kek, kekId);
builder.Services.AddKeywardSoftwareClientApi();

// Per-token rate limiting for the software-client read API (registered here because the rate-limiter
// service extension lives in the host's ASP.NET Core stack).
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

var app = builder.Build();

// Apply migrations and seed the demo tenant/project (dev convenience).
await using (var scope = app.Services.CreateAsyncScope())
{
    var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
    await db.Database.MigrateAsync();

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
app.UseRateLimiter();

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.MapKeywardApi();          // management/admin API (route-scoped; unauthenticated for now)
app.MapKeywardClientApi();    // software-client read API (token-authenticated + rate limited)

app.Run();
