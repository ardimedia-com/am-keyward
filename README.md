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

AM KEYWARD is library-first: you add it to your own Blazor Web App and it brings its services, API, and
feature UI. There are no published NuGet packages yet, so reference the projects directly
(`Am.Keyward.Infrastructure`, `Am.Keyward.Api`, `Am.Keyward.Ui.Blazor`) via `ProjectReference` (e.g. as a
git submodule) until packages ship.

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

// Tell the embedded UI which tenant/project to operate in (from your own selection logic).
builder.Services.AddScoped<IKeywardWorkspaceContext, MyWorkspaceContext>();

// Optional: the software-client read API + its named "Keyward.SoftwareClient" bearer scheme.
builder.Services.AddKeywardSoftwareClientApi();
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
app.UseKeywardCurrentUser();                     // middleware: current user per HTTP request
```

**Tenant** selection stays yours (it is app-specific) — set `ITenantScopeSetter` per request/circuit from
your own logic (the reference shell pins a fixed demo tenant via `DemoTenantCircuitHandler`).

**3. Discover the feature pages.** The pages live under the `/amkeyward/*` route prefix (so they can't
collide with your routes). Add the RCL assembly to both the endpoint and the router:

```csharp
app.MapRazorComponents<App>()
   .AddInteractiveServerRenderMode()
   .AddAdditionalAssemblies(typeof(Am.Keyward.Ui.Blazor.KeywardRoutes).Assembly);
```
```razor
<Router AppAssembly="..." AdditionalAssemblies="new[] { typeof(Am.Keyward.Ui.Blazor.KeywardRoutes).Assembly }" />
```

**4. Drop the navigation into your layout** (localized, auth-aware, no hardcoded routes):

```razor
<KeywardNav />
```

**Styling and routes come for free.** The UI theme is component-scoped CSS in the RCL, so it is folded into
your app's standard `{Assembly}.styles.css` bundle automatically — no extra stylesheet `<link>` needed.
Override the look by redefining the `--kw-*` CSS variables on `.keyward-ui`. The feature routes are the
`/amkeyward/*` namespace; use the `KeywardRoutes` constants for links.

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
    migrations:
    ```csharp
    await using var scope = app.Services.CreateAsyncScope();
    await scope.ServiceProvider.GetRequiredService<KeywardDbContext>().Database.MigrateAsync();
    ```
  - and/or run a periodic safety-net (re-applies pending migrations if the DB is swapped under a running
    app) — see the reference shell's `DatabaseMigrationBackgroundService` and the `DatabaseMigration`
    config section (`Enabled`, `CheckIntervalSeconds`);
  - or apply them out-of-band in your deploy step (`dotnet ef database update`).
- **Two database logins (production).** Migrate with an elevated DDL login and run with a **least-privilege
  login that is an RLS subject** (not `db_owner`/`sysadmin`, which would bypass row-level security). Local
  development uses Integrated Security for both. See [docs/database-logins.md](docs/database-logins.md).

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
