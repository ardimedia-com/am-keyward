# AM KEYWARD

> ⚠️ **Early development (pre-1.0).** Not production-ready. The security design has **not** yet been
> externally reviewed — do not store real secrets in it yet.

**AM KEYWARD** is an open-source, .NET-native, **library-first** credential & secrets manager: a
building block you embed in your own .NET environment (and can offer to your own users), plus an
optional **standalone reference app**.

It covers two halves equally:

- **Software credentials** — machine/integration secrets (API keys, connection strings), scoped per
  project & environment, fetched by your software via an API.
- **Human vaults** — personal & team password vaults, shared to groups or individuals.

## What it is / is not

- **Is:** an embeddable toolkit + reference app that you self-host and operate.
- **Is not:** a hosted service, and not a HashiCorp-Vault-at-scale replacement.

There is no central, vendor-hosted AM KEYWARD. **Each operator runs and secures their own deployment**
(key custody, database, hardening) — see [SECURITY.md](SECURITY.md).

## How the human-vault half differs from Bitwarden / KeePass

AM KEYWARD is **not** trying to out-feature a dedicated password manager. Its human vaults exist so that
**one** system covers both halves of an organization's secrets — the machine credentials your software
reads at runtime **and** the passwords your people share — under one data model, one login, one admin, one
**tamper-evident audit log**, with the same envelope encryption and the same operator-owned KEK.

- vs **KeePass** (a local encrypted file): AM KEYWARD is server-side and multi-user with central
  authorization grants, tenancy isolation, versioning and audit — not a file you sync by hand.
- vs **Bitwarden** (an excellent hosted/self-hosted password manager): AM KEYWARD is **embeddable** in your
  own .NET app and unifies software credentials with human vaults; it is **not** a hosted service and does
  not (yet) ship browser-extension autofill or zero-knowledge vaults (zero-knowledge is the v0.2 goal,
  gated on an external review). If you only need a password manager for people, use Bitwarden.

## Threat model (summary)

What AM KEYWARD is designed to resist, and what it explicitly does **not**:

**In scope / mitigated**

- **Database compromise alone** — a stolen DB backup yields only ciphertext; the KEK lives outside the
  database, so without the KEK store the envelopes cannot be decrypted.
- **Cross-tenant / cross-user leakage** — defense-in-depth: a composite application query filter, a
  server-authoritative active tenant, **SQL Server row-level security** via `SESSION_CONTEXT`, and a
  least-privilege runtime login that is itself an RLS subject. Exercised by an adversarial isolation test
  gate.
- **Ciphertext replay across slots** — AEAD AAD binds every ciphertext to its exact tenant / owner /
  project / environment / item / version, so a Dev/old ciphertext cannot be moved into a Prod/current row.
- **Audit tampering** — a per-tenant hash chain, single-writer/serializable append, with an out-of-band
  chain-head checkpoint so a DB admin who rewrites history is detectable.
- **Insider / admin abuse of emergency access** — server-side recovery is **dual-control** break-glass with
  an out-of-band, append-only non-repudiation trail.
- **Secrets in telemetry** — the encrypted envelope is redacted from logs; problem-details and provider
  exceptions never echo values or connection strings.
- **Token abuse** — software-client tokens are env-scoped (scope from the persisted token, never the
  request), hashed at rest, rotatable/revocable, rate-limited, with advance-expiry notifications.

**Out of scope / operator-owned**

- **KEK custody and loss** — losing the KEK is total, unrecoverable data loss; the operator backs it up
  (offline, split) and rehearses the restore. See the [operations runbook](docs/operations-runbook.md).
- **The escrow read path returns plaintext by design** — for server-side vaults and the software API, the
  server can decrypt; this is the acknowledged trade-off of escrow (zero-knowledge human vaults are v0.2).
- **Host hardening** — OS, network exposure, TLS, and the security of the identity provider are the
  operator's responsibility.
- **No external security review yet** (pre-1.0) — do not store real secrets until one has been done.

## Security & operations

- [SECURITY.md](SECURITY.md) — reporting, operator responsibilities, no-warranty.
- [Operations & KEK/DR runbook](docs/operations-runbook.md) — key custody, backup/restore order, KEK
  rotation and compromise response, monitoring/health endpoints, break-glass, GDPR erasure.

## Embedding in your own ASP.NET Core / Blazor app

AM KEYWARD is library-first: you add it to your own **.NET 10 Blazor Web App (interactive server)** and it
brings its services, API, and feature UI. Reference it either as the published **preview NuGet packages**
(`dotnet add package Am.Keyward.Infrastructure --prerelease`, same for `Am.Keyward.AspNetCore`,
`Am.Keyward.Ui.Blazor`, and `Am.Keyward.Api` if you expose the REST APIs) or as direct `ProjectReference`s
(e.g. a git submodule).

**0. Prerequisites** — the Keyward pages are interactive-server and `[Authorize]`-protected, so your app
needs interactivity, auth-state cascading and (that's all — localization comes with `AddKeywardUi`):

```csharp
builder.Services.AddRazorComponents().AddInteractiveServerComponents();
builder.Services.AddCascadingAuthenticationState();   // [Authorize]/<AuthorizeView> need the cascade
// ...plus your own cookie/OIDC authentication setup.
```

**1. Register the services** — one call wires up the EF Core `DbContext` (schema `amkeyward`), envelope
crypto, audit, vaults, tokens, break-glass and monitoring:

```csharp
// The KEK comes from your provider (Azure Key Vault / HSM / a protected file) — NEVER from the DB/appsettings.
var keywardConn = builder.Configuration.GetConnectionString("Keyward")!;
var (kek, kekId) = LoadKekFromYourProvider();
builder.Services.AddKeyward(keywardConn, kek, kekId);

// Prefer this overload when the KEK stays in a KMS/HSM (the raw key never enters the process). Supply your
// own IKekProvider, or a KeyRingKekProvider holding the current + prior versions during a KEK rotation:
// builder.Services.AddKeyward(keywardConn, sp => new KeyRingKekProvider(currentKekId, keksByVersion));

// Tell the embedded UI which tenant to operate in (from your own selection logic), and register the UI's
// own services (circuit-scoped state + localization for the Keyward strings, six languages built in).
// ProductName is what your users see (browser tab, brand, texts, e-mails); default "AM KEYWARD".
// PublicBaseUrl (optional) enables absolute links in notification e-mails sent by background jobs.
// NotificationLanguage (optional) sets the language for those background e-mails (account e-mails
// follow the request culture); default English.
builder.Services.AddScoped<IKeywardWorkspaceContext, MyWorkspaceContext>();
builder.Services.AddKeywardUi(o =>
{
    o.ProductName = "Contoso Secrets";
    o.PublicBaseUrl = "https://secrets.contoso.com";
    o.NotificationLanguage = "en";
});

// Optional — transient notifications ("Vault created", "Moved", errors). Keyward depends only on the
// IKeywardNotifier port. Standalone it shows its own BlazorBlueprint-styled toast (KeywardToastHost). If
// your app already has a toast system, override the port so Keyward's notifications use it and are
// indistinguishable from the rest of your app (registered with TryAdd, so your registration wins):
builder.Services.AddScoped<IKeywardNotifier, MyToastNotifier>();   // e.g. routes onto BlazorBlueprint's BbToast
```

**2. Bind identity at the edge.** The libraries are identity-agnostic: they read `ICurrentUser` /
`ICurrentTenant`, which you set from *your* auth. Your auth layer stamps the Keyward `AppUser` id onto the
signed-in principal as the `KeywardClaims.UserId` claim (however you map it — ASP.NET Identity, external
OIDC, ...); the `Am.Keyward.AspNetCore` package then establishes the current **user** on both the HTTP and
the Blazor-circuit path for you:

```csharp
builder.Services.AddKeywardBlazorUserScope();   // circuit handler: current user per Blazor circuit
// ...
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();                            // MUST come after auth — tokens bind to the signed-in user
app.UseKeywardCurrentUser();                     // middleware: current user per HTTP request
```

- **`KeywardClaims.UserId` must be a GUID that exists in Keyward's `Users` table (`AppUser`).** Keyward does
  not create these rows for you: on first sign-in, create the `Tenant`, the `AppUser` and a
  `TenantMembership` (role `TenantAdmin` for managers) through `KeywardDbContext` — see the reference
  shell's `KeywardUserClaimsPrincipalFactory` (JIT `AppUser` + membership, first user becomes system admin)
  and `Demo.EnsureSeededAsync` (tenant seed). Without these rows the pages render empty and read-only.
- **Tenant selection stays yours** (it is app-specific): register a `CircuitHandler` that calls
  `ITenantScopeSetter.SetTenant(...)` in `OnCircuitOpenedAsync` with the same tenant your
  `IKeywardWorkspaceContext` returns — see the reference shell's 15-line `DemoTenantCircuitHandler`. If the
  circuit scope is missing, every page fails with *"Tenant scope mismatch"*.
- **Symptom check:** a Keyward page stuck at "Loading…" for a signed-in user means the circuit has no
  Keyward user — verify `AddKeywardBlazorUserScope()` is registered and the principal carries a valid-GUID
  `KeywardClaims.UserId`.

**3. Discover the feature pages.** The pages live under the `/amkeyward/*` route prefix (so they can't
collide with your routes). Add the RCL assembly to the endpoint and the router — and route through
`AuthorizeRouteView` (a plain `RouteView` ignores `[Authorize]`):

```csharp
app.MapRazorComponents<App>()
   .AddInteractiveServerRenderMode()
   .AddAdditionalAssemblies(typeof(Am.Keyward.Ui.Blazor.KeywardRoutes).Assembly);
```
```razor
<Router AppAssembly="..." AdditionalAssemblies="new[] { typeof(Am.Keyward.Ui.Blazor.KeywardRoutes).Assembly }">
    <Found Context="routeData">
        <AuthorizeRouteView RouteData="routeData" DefaultLayout="typeof(Layout.MainLayout)">
            <NotAuthorized>@* redirect to your login *@</NotAuthorized>
        </AuthorizeRouteView>
    </Found>
</Router>
```

**4. Drop the navigation into your layout** (localized, auth-aware, no hardcoded routes):

```razor
<KeywardNav />
```

Style its `.nav-link` / `.nav-group-label` classes in your layout (see the reference shell's
`NavMenu.razor.css`) — the nav deliberately adopts the host's look. `KeywardNav` lists the end-user pages;
place links to the admin pages (`KeywardRoutes.Groups`, `KeywardRoutes.DefaultEnvironments`) in your own
administration section.

**5. Optional REST APIs.** The software-client read API (deployed apps fetch their secrets with a bearer
token) needs the service registration, the rate-limiter middleware AND the endpoint mapping — the endpoints
don't exist otherwise:

```csharp
builder.Services.AddKeywardSoftwareClientApi();  // "Keyward.SoftwareClient" scheme + rate-limiter policy
// ...
app.UseRateLimiter();                            // the mapped group requires the middleware
app.MapKeywardClientApi();                       // GET /keyward/api/v1/secrets[/{key}]
// Optional management REST API, guarded by YOUR admin policy:
app.MapKeywardApi(authorizationPolicy: "YourAdminPolicy");
```

**Styling and routes come for free.** The UI theme is component-scoped CSS in the RCL, so it is folded into
your app's standard `{Assembly}.styles.css` bundle automatically — no extra stylesheet `<link>` needed (the
template's existing bundle link covers it). Override the look by redefining the `--kw-*` CSS variables on
`.keyward-ui`; dark mode / color themes react to `html.dark` / `html[data-theme="…"]` if your host toggles
them (see the reference shell's `js/keyward-theme.js`) — with no toggling you get the light default. The
vault/application pages use `<KeywardUi Fill="true">`: in a plain layout they render with a normal page
scroll; for the pinned header + independently scrolling panes, make your content container a fixed-height
flex column and add `.your-content:has(> .keyward-ui.kw-fill) { overflow: hidden; display: flex;
flex-direction: column; }` (see the reference shell's `MainLayout.razor.css`). To pin the UI language, add
`UseRequestLocalization` with your supported cultures; without it the pages follow the server culture
(en/de/fr/it/es/pt ship built in). The feature routes are the `/amkeyward/*` namespace; use the
`KeywardRoutes` constants for links.

### Database & migrations

- **You provide the database via the connection string** passed to `AddKeyward(connectionString, …)`.
  AM KEYWARD is **SQL Server only** (incl. Azure SQL). The reference shell reads it from
  `ConnectionStrings:Keyward` (override it in `appsettings.json`, an environment variable, or user-secrets;
  it falls back to a `localhost` dev default). AM KEYWARD never hardcodes the database name — that lives in
  *your* connection string.
- **It coexists in your database.** All AM KEYWARD tables live in a dedicated **schema `amkeyward`** with a
  **schema-scoped migrations-history table**, so you can point it at the same database your host app already
  uses without colliding with your tables or your own EF migrations.
- **Migrations are not automatic just from the connection string.** `AddKeyward` only registers the
  `DbContext`; the connection string only says *where* the database is. Apply Keyward's migrations one of
  these ways (the reference shell does the first two):
  - call `MigrateAsync()` at startup — this **creates the database if it doesn't exist** and applies pending
    migrations (`using Am.Keyward.Infrastructure.Persistence;`):
    ```csharp
    await using var scope = app.Services.CreateAsyncScope();
    await scope.ServiceProvider.GetRequiredService<KeywardDbContext>().Database.MigrateAsync();
    ```
  - and/or run a periodic safety-net (re-applies pending migrations if the DB is swapped under a running
    app) — see the reference shell's `DatabaseMigrationBackgroundService` and the `DatabaseMigration`
    config section (`Enabled`, `CheckIntervalSeconds`);
  - or apply them out-of-band in your deploy step (`dotnet ef database update`).
- **Two database logins (production).** Migrate with an elevated DDL login and run with a **least-privilege
  login that is an RLS subject** (not `db_owner`/`sysadmin`, which would bypass row-level security). Note
  this **excludes the startup-`MigrateAsync` option in production**: the app runs on `amkeyward_app` (which
  cannot DDL and must not be `db_owner`, or RLS is silently off), so apply migrations out-of-band with the
  migrator login and give `AddKeyward` only the runtime connection string; startup-migrate is for
  development, where one Integrated-Security login plays both roles. Run `db/setup-logins.sql` once after
  the first migration. See [docs/database-logins.md](docs/database-logins.md).

## UI design principle — match BlazorBlueprint

The embedded Keyward UI **MUST follow BlazorBlueprint's behaviour and layout** — its controls, spacing,
interaction patterns and notifications should be indistinguishable from a BlazorBlueprint host, so Keyward
looks and feels native inside one. Keyward stays **self-contained** (no hard dependency on BlazorBlueprint,
its own `--kw-*` tokens and components) so it also embeds anywhere; this principle governs that its own UI is
kept **visually and behaviourally aligned** with BlazorBlueprint's conventions.

Two layers realise this:

- **Behaviour via ports.** Where a host has a better-integrated primitive, Keyward depends on a small port,
  not on the concrete control, and the host wires the real thing. The transient-notification port
  `IKeywardNotifier` is the reference: a BlazorBlueprint host overrides it to use **`BbToast`** (real BB,
  identical to the rest of the app); standalone, Keyward's built-in `KeywardToastHost` renders a
  **BlazorBlueprint-styled** toast (bottom-right, auto-dismiss, per-kind accent) that mimics it.
- **Layout via the token contract.** Keyward's own components style against `--kw-*` tokens chosen to match
  BlazorBlueprint's look; a host maps them to its theme.

**Consequence for contributions:** new Keyward UI, and any review of existing UI, is measured against
BlazorBlueprint — if a control or message deviates from how BlazorBlueprint would present it, adjust Keyward
(or add a port the host fills), don't diverge. The current UI is being reviewed against this and adjusted
where it deviates (the notification split — success → toast, errors → inline — was the first pass).

## Tech

.NET 10 · Blazor Server · ASP.NET Core · EF Core (Microsoft SQL Server) · MIT licensed.

## Build

```
dotnet build Am.Keyward.slnx
dotnet test Am.Keyward.slnx
```

Requires the .NET 10 SDK; data/integration tests require a local SQL Server reachable on `localhost`
via Integrated Security.

## Documentation

End-user & operator documentation lives in [`docs/`](docs/) and grows as features ship:

- [Software-client API](docs/software-client-api.md) — how a deployed app fetches its secrets with a token.
- [Database logins](docs/database-logins.md) — the least-privilege runtime login vs. the migration login
  that underpins tenant isolation.

## License

[MIT](LICENSE) © 2026 Ardimedia Anstalt
