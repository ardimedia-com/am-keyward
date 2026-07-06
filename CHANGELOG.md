# Changelog

All notable changes to this project are documented here, following
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The project is pre-1.0.

## [Unreleased]

### Added

- **E-mail confirmation on registration (enumeration-safe).** Registration now creates the account inactive
  and sends a confirmation link (`RequireConfirmedAccount`); it always shows the same "check your e-mail"
  result whether or not the address is already registered, so it no longer leaks account existence via a
  duplicate-e-mail error. A new `/account/confirm-email` page activates the account from the link, after which
  the user can sign in (an unconfirmed account cannot). Delivery reuses `IAccountEmailSender` (reference
  maildrop sender); localized in all six UI languages.
- **Pluggable KEK provider.** A new `AddKeyward(connectionString, Func<IServiceProvider, IKekProvider>)`
  overload lets a host supply its own key-encryption-key provider (Azure Key Vault / AWS KMS / HSM), so the
  raw KEK need never enter the application process — the previous `byte[]` overload now delegates to it and
  stays for the file/dev case. A new `KeyRingKekProvider` holds the current KEK version plus prior versions,
  so a KEK rotation can wrap new values under the new version while existing values still unwrap under their
  original one during the overlap. (A background re-wrap job that migrates existing values to the new version
  is still to come; the provider is the enabling piece.)
- **Self-service password reset.** Forgot-password and reset-password pages (statically rendered): a user
  requests a single-use reset link and sets a new password. A successful reset **clears a brute-force lockout**
  so the user regains access immediately (but never clears an administrative disable). The flow is
  enumeration-safe (the forgot page always shows the same confirmation) and links from the sign-in page.
  Delivery goes through a new `IAccountEmailSender`; the reference shell ships a file **maildrop** sender
  (writes the e-mail to a local folder, configurable via `AccountEmail:MaildropPath`) that a real deployment
  replaces with an SMTP sender.
- **Admin user-management UI** (system-admin only, at `/account/admin/users`): shows each account's status
  (active / locked out / disabled) and lets an admin **unlock** a brute-force lockout, or **disable** and
  **re-enable** an account. This is the recovery path the auth policy requires beyond lockout auto-expiry
  (the only way back in for an administratively disabled account, and the fast path for a stuck user). An
  admin cannot disable their own account; every action is audited. Statically rendered, antiforgery-protected.

### Security

- **Software-client token lifecycle is now audited.** Issuing, rotating, revoking and updating a token
  writes a tamper-evident audit-chain entry (attributed to the acting user), so minting or revoking a
  credential leaves a trace; previously these operations wrote nothing.
- **Admin secret access is now attributed.** The management API resolves the signed-in user, and the
  software-secret service records that actor on store/read/delete (and the UI secret-detail read) instead of
  a null actor. The machine (token) read path stays unattributed, as it has no user.
- **A local user is now unique by external id.** A filtered unique index on `Users(ExternalId)` for local
  (null-issuer) accounts, plus a SQL app-lock around the just-in-time user creation, so two concurrent
  first-time sign-ins can neither create duplicate `AppUser` rows for one user nor both become System Admin.
  Migration `LocalUserUniqueIndex`.
- **The tenant-less (personal-vault) audit hash chain no longer forks.** The audit-chain writer reads the
  chain head on the app connection, which is subject to row-level security; while a tenant was in scope (every
  Blazor circuit) the head of a `TenantId = null` chain was hidden, so each personal-vault operation re-sealed
  sequence 1 and the tamper-evident chain silently forked (and health went Unhealthy). A trusted, FILTER-only
  `SESSION_CONTEXT('SystemBypass')` read bypass — set only by the audit writer around its head read — lets it
  see the correct head. BLOCK predicates never honor the bypass, so no cross-tenant write is ever enabled.
- **The ops-monitor and KEK-integrity sweeps are no longer blind.** Running tenant-less, they were filtered by
  RLS to zero rows, so the KEK-integrity check falsely reported "consistent, 0 checked" and no tenant's audit
  chain was verified. They now run under the same FILTER-only system-read bypass (`SystemReadScope`), so they
  scan every tenant's encrypted versions and audit chains. Migration `AuditSystemReadBypass`.
- **The management API now verifies tenant membership** before it trusts the route's `{tenantId}`. Previously
  it set the server-authoritative tenant scope straight from the caller-supplied route id with only an
  "authenticated" check, so any signed-in user could read/write another tenant's software secrets and
  mint/rotate/revoke its tokens. A new `ITenantMembership` port gates the route tenant against the signed-in
  user's membership (system admins are members of every tenant); non-members get 403. New `TenantMemberships`
  table + migration.

- **Data Protection key ring is now persisted** (reference shell) to `%ProgramData%\Ardimedia\Am.Keyward\keys`
  with `SetApplicationName("Am.Keyward")` and DPAPI at-rest protection on Windows, best-effort with a
  fall-back to the default store if the folder is not writable. Previously the key ring lived at the
  framework default location, so every app restart/redeploy regenerated the keys — signing all users out and
  invalidating outstanding Identity reset/confirmation tokens.
- **Password policy raised to a 12-character minimum** (require upper/lower/digit; symbols not mandated) on
  Identity and on the registration form, up from the framework default of 6.
- **"Remember me" is now opt-in.** The login page ships an unchecked "keep me signed in" box; sign-in and
  registration no longer force a persistent cookie (`isPersistent` was hardcoded `true`), so on a shared or
  kiosk device the next person no longer inherits a signed-in vault session.
- **Software-secret decryption pins the AES-GCM tag length** to the 16-byte constant instead of trusting the
  stored (DB-writable) tag length, and rejects any value whose tag length differs — closing a
  tag-truncation forgery-resistance downgrade.
- **The read-API rate limiter no longer keys its in-memory partitions on the raw bearer token** — it hashes
  the Authorization header (SHA-256) so a limiter dump reveals no token plaintext.
- **Break-glass grants now carry an optimistic-concurrency token** (SQL Server rowversion), so two racing
  approve/reject/consume calls can no longer both succeed — an approved single-use grant cannot be consumed
  twice. `ConsumeAsync` additionally re-checks system-admin (mirroring request/approve/reject), so a user
  de-privileged after approval can no longer consume an outstanding grant. Migration `BreakGlassConcurrency`.

### Fixed

- Embedded UI (`Secrets` page): saving or creating a secret value called the busy-guarded `ViewAsync`
  from inside an already-running guarded action, so it early-returned — the detail view was never
  refreshed and the just-entered plaintext value was left in the input with Save still enabled. Extracted
  an unguarded `LoadDetailAsync` loader and clear the add-value field after a successful create.
- Rotating a software-client token without an explicit new expiry silently cleared its expiry (turning a
  time-limited token into a non-expiring one); rotation now preserves the token's existing expiry unless a
  new one is supplied.

### Changed

- **Breaking (library API):** the central access-policy port `IAuthorizationService` is renamed to
  `IKeywardAccessPolicy`, so it no longer collides with ASP.NET Core's
  `Microsoft.AspNetCore.Authorization.IAuthorizationService` in an embedding host (no more alias-`using`).
  Consumers referencing the port by name update to the new name; behaviour is unchanged.
- Blazor circuit retention raised to 30 minutes (`DisconnectedCircuitRetentionPeriod`) so a short network
  drop or device sleep returns to a live session instead of a full reload.
- The audit-chain append lock is now **per tenant** (`Keyward_AuditChain_{tenantId}`) instead of one
  installation-wide lock, so audited operations (including reads) for different tenants no longer serialize
  against each other. A multi-tenant save takes its locks in a deterministic order to avoid deadlock.
- The scoped `KeywardDbContext` now **clears its change tracker after each save**, so a long-lived Blazor
  Server circuit no longer accumulates tracked entities (memory) or serves stale, identity-resolved reads
  after another circuit updated a row. This gives the long-lived context short-lived-context behaviour
  between operations without the larger `AddDbContextFactory` refactor (which would rewire the shared audit
  unit-of-work across the persistence layer for a perf-only gain); safe because no operation reuses a tracked
  entity across two saves.

- Accessibility and layout hardening of the embedded UI pages (`Secrets`, `Tokens`, `VaultWorkspace`) and
  the reference shell's `NotFound` page: associate `<label>`s with their inputs, add `aria-label`s to
  placeholder-only filter/select controls, mark status/error notices with `role="status"`/`role="alert"`,
  set `autocomplete="off"` on secret-value inputs, wrap wide data tables in a horizontal-scroll container
  (new `.table-scroll` class) and move row-action flex layout off the `<td>` onto an inner element, and use
  an `<h1>` on the not-found page so `FocusOnNavigate` and the heading hierarchy work.

## [0.1.0-preview] - 2026-06-22

First published (pre-1.0 **preview**) release on nuget.org: the full v0.1 build (Slices 0–8) — software
credentials, server-side human vaults, tenancy/isolation, the embeddable Blazor UI, and the ops/compliance
hardening below. Published as a `-preview` prerelease because the security design has **not** yet been
externally reviewed — do not store real secrets yet (see SECURITY.md).

### Added

- Published as **NuGet packages** (`Am.Keyward.Core`, `Am.Keyward.Contracts`, `Am.Keyward.Infrastructure`,
  `Am.Keyward.Api`, `Am.Keyward.Ui.Blazor`) so a Blazor Web App can embed AM KEYWARD via `dotnet add package`;
  the RCL ships its static web assets (the scoped theme) and localization satellites inside the package, with
  SourceLink and symbol (`.snupkg`) packages. A tag-driven release workflow packs and pushes them to
  nuget.org.
- The RCL theme is now **self-applying**: the embedded-UI styling lives in a component-scoped
  `KeywardUi.razor(.css)` wrapper (its own `--kw-*` CSS variables, `::deep` for the page markup), so it is
  folded into the consuming app's standard `{Assembly}.styles.css` bundle automatically — a host needs **no**
  extra stylesheet link, just the Blazor styles bundle it already references. Scoped under `.keyward-ui` so
  it can never restyle the host's own buttons/inputs/tables; override the look via the `--kw-*` variables.
- `KeywardNav` component + `KeywardRoutes` constants: a reusable, localized, auth-aware navigation for the
  Keyward sections so a host never hardcodes Keyward's route strings. The reference shell's sidebar uses it.
- Slice 7 (part 6) — break-glass mechanism: dual-control emergency access to server-side material. A
  System Admin requests access to a scoped resource with a reason; a **different** System Admin must
  approve it (no self-approval, enforced in the domain) before it can be consumed once, within a validity
  window. Every transition is written both to the tamper-evident audit chain (`BreakGlass` action) and to
  an out-of-band, append-only **hash-chained file sink** (`IBreakGlassSink` / `FileBreakGlassSink`) that
  lives outside the database — so the DB admin whose access is recorded cannot rewrite their own trail
  (non-repudiation). New `BreakGlassGrant` aggregate + `IBreakGlassService` (request/approve/reject/consume),
  installation-global table (system-admin gated, not tenant-filtered), migration `BreakGlass`, and a
  `Keyward:BreakGlass` config section (`SinkFilePath`, `ValidityMinutes`).
- Slice 7 (part 5) — DSGVO crypto-shredding: audit entries now store an opaque, stable **pseudonym** for
  the actor instead of the user id. The actor's PII (display name, external id) lives in a new
  `AuditSubjects` table encrypted under a per-subject DEK (envelope, KEK-wrapped, AAD-bound to the
  pseudonym), via the new `IAuditSubjectDirectory` (find-or-create on append, admin read, erase). Erasure
  clears the ciphertext so the PII becomes irrecoverable, while the pseudonym stays in the immutable audit
  chain — the chain still verifies intact after a subject is erased. The directory is installation-global
  (a subject is stable across tenants, not tenant-filtered or under RLS) and holds only ciphertext.
  Migration `CryptoShredding`. (`AuditRequest.ActorPseudonymId` renamed to `ActorUserId` — the sink does
  the pseudonymizing.)
- Slice 7 (part 4) — ops hardening: telemetry redaction, backup/restore KEK-integrity job, and health
  monitoring. The `EncryptedValue` envelope now renders as `[REDACTED]` so it can never leak ciphertext,
  nonce, tag, wrapped DEK or KEK id into any log sink (Serilog or `Microsoft.Extensions.Logging` both call
  `ToString()` on a logged object). A new `IKekIntegrityVerifier` scans every stored envelope and reports
  any whose KEK id the provider can no longer resolve — the signal that a database was restored without its
  matching KEK store, or a KEK version was retired before its rows were re-wrapped (it checks id
  resolvability, no per-row unwrap); the `IKekProvider` port gained `CanResolve(kekId)` for the overlap
  window. A periodic `OpsMonitorBackgroundService` verifies KEK integrity, walks each tenant's audit hash
  chain, and counts tokens nearing expiry, logging anomalies and publishing an `OpsHealthSnapshot`. Two
  health checks — a live `kek-availability` wrap/unwrap probe and a cached `ops-monitor` reading — are
  exposed at `/health` (liveness) and `/health/ready` (readiness).
- Branding & multi-language UI: a new key-in-tile SVG icon is the favicon and the sidebar brand mark. The
  UI is now localizable in six languages — English (default), German (Swiss/Liechtenstein spelling),
  French, Italian, Spanish and Portuguese — using `IStringLocalizer` + `.resx` (a shared `SharedResource`),
  `RequestLocalization` with a culture cookie. The non-English translations are best-effort and meant to be
  refined by the community. The whole UI is translated — navigation, sign-in/registration, home, the header
  bar, and the full page bodies of the personal/team vaults workspace, software credentials and client
  tokens (labels, buttons, descriptions, table headers, placeholders and status messages), plus the
  not-found and error pages.
- In-app help: every page explains what its entity is and how to use it, in plain language. The personal
  and team vault intros, the software-credentials and client-tokens pages now carry fuller descriptions,
  and the credentials/tokens pages add a "how it works" note covering the end-to-end flow (deployed
  software reads secrets at runtime with a Bearer client token; rotate/revoke on leak; values change
  without an app redeploy). All help text is localized in the six UI languages.
- Top header bar: a full-width header above the content carries a language switcher (all six languages) and
  the signed-in user's name; clicking the name opens a menu with "View profile" and "Sign out". A new
  `/account/profile` page shows the account's e-mail and system-admin status. The language switcher and
  user menu moved out of the sidebar into this header.
- Software credentials UI — the `/secrets` page is now a list-first manager: it lists the project's secret
  keys (filterable), View shows each environment's current value (masked, with Reveal) and lets you set or
  change the value per environment, Add creates a key/value, and Delete… removes a secret via its detail.
  Backed by new `ListSecretsAsync` / `GetSecretAsync` / `DeleteSecretAsync` service methods.
- Client tokens — a token now has an editable name and a free-text note: issue with a note, edit the
  name/note inline (panel above the list), and the list shows the note and a status badge. (Migration
  `SoftwareClientTokenNote`.)
- Vaults UI refinements: every list (vaults, folders, items, and the client-token list) gains a filter
  box for longer lists; an item's detail / add / edit panel now appears above the list on the same page
  (the list stays visible); and deletion is never one-click — choosing “Delete…” on an item opens its
  detail with a Delete button there, and folder deletion is confirmed inline. The content area spans the
  full page width.
- Vaults UI — list-first workspace, split into separate **Personal vaults** (`/vaults/personal`) and
  **Team vaults** (`/vaults/team`) pages. Each lists vaults → select one → lists its folders and items;
  choosing View / Add / Edit / Delete on an item shows it with the matching actions. Login items have
  name / url / username / password / note fields (password masked, with reveal); other types a single
  value. Each vault can import a browser password CSV (Edge / Chrome). Team pages add sharing (grant a
  user Read / Write / Manage and see current shares). Every entity carries a short in-page explanation,
  and all pages now use the browser title "AM KEYWARD".
- Vaults — full CRUD + structured logins + import (service): items can be edited (a re-encrypted new
  version) and deleted; folders and vaults can be renamed and deleted (vault deletion also removes its
  access grants); a Login item's content is structured as url / username / password / note (JSON inside the
  encrypted value, shared by UI and importer via `LoginContent`); and logins can be bulk-imported from a
  browser password export (`ImportLoginsAsync`). `GetItemAsync` returns an item with its decrypted content
  for viewing/editing.
- Slice 7 (part 1) — ops hardening: an audit-chain verifier (`IAuditChainVerifier`) walks a tenant's
  hash chain in sequence order and recomputes each link, detecting a tampered entry, a broken previous-hash
  link, or a sequence gap; the chain hash moved to a shared helper so the writer and verifier cannot drift.
  Sign-in lockout is enabled (5 failed attempts → a 5-minute lockout) to blunt password brute-forcing.
- Slice 7 (part 2) — audit single-writer: the per-tenant audit sequence and chained hashes are now assigned
  at commit by a `SaveChanges` interceptor under a session-scoped SQL Server application lock, so concurrent
  appends (even across instances) cannot fork a tenant's chain or collide on its sequence — replacing the
  previous read-max-then-insert that could race.
- Slice 7 (part 3) — runtime migration safety-net: a background service periodically re-checks both
  contexts for pending migrations and applies them, so the app recovers if the database is
  swapped/restored under the running instance (the startup migration would otherwise be bypassed). EF
  serializes across instances via its migration lock; best-effort and configurable via the
  `DatabaseMigration` section (`Enabled`, `CheckIntervalSeconds`). The cleaner operational fix — recycle
  the app whenever the DB is swapped — still applies.
- Slice 6b (part 3) — tenant ("team") vaults + sharing: create a tenant-owned vault (the creator gets a
  Manage grant) and share it with other users at Read / Write / Manage via `AccessGrant`s; tenant vaults
  are reachable only through a grant. The central `IAuthorizationService` now evaluates vault grants, with
  tenant isolation (query filter + RLS) as the outer boundary — cross-tenant grants are forbidden. New
  `AccessGrants` table (under row-level security) + migration. The `/vaults` page gained a Team-vaults
  section (create, list, share with a user, view current shares). Group-based grants are deferred. Covered
  by a sharing test (creator Manage; grantee gets exactly the granted permission; non-grantee denied;
  another tenant cannot see the vault).
- Slice 6b (part 2) — My Vault UI + shell theme: a `/vaults` page to create personal vaults, add folders
  and typed items, and reveal an item's decrypted value on demand. The whole shell was restyled into a
  cohesive theme (dark sidebar, light content, cards/tables/badges/forms) with hand-written CSS variables
  — no Bootstrap/Tailwind dependency — inspired by the win-smtp-relay admin look. Home is now a real
  landing page, and the nav reflects sign-in state.
- Slice 6b (part 1) — personal human vaults: server-side envelope-encrypted vaults owned by a user
  (tenant-less), with folders and typed, versioned items (`IVaultService`: create vault/folder/item, read,
  list), server-authoritative on the current user. Vault tables carry a denormalized isolation boundary
  (`TenantId` for tenant vaults, `OwnerUserId` for personal vaults) enforced by the EF query filter AND
  extended SQL Server row-level security — a two-column predicate over `SESSION_CONTEXT('TenantId')` /
  `SESSION_CONTEXT('UserId')` (the connection interceptor now stamps `UserId` too). Current-user
  resolution is unified on an ambient context set at the host edge (an HTTP middleware and the Blazor
  circuit, from the authentication state). Tenant/group vaults, grant-based sharing and the vault UI follow.

- Slice 6a — admin sign-in and protected management API: the standalone reference shell now uses
  ASP.NET Core Identity (cookie auth) for human sign-in, kept in the shell so the libraries stay
  identity-agnostic (own `amkeyward_identity` schema and migration). The first registered account becomes
  the system administrator; sign-in maps to a domain `AppUser` just-in-time and stamps a `keyward:user_id`
  claim. The management API (create secrets, issue/rotate/revoke tokens) now requires a signed-in admin,
  and the Blazor pages are behind authorization with a redirect to sign-in. Added a `/tokens` management
  page (issue/rotate/revoke, token shown once) and sign-in/registration/sign-out.
- Slice 5 — software-client API authentication: per-(project, environment) Bearer tokens
  (`SoftwareClientToken`) so a deployed app reads only its own environment's secrets and a leaked token
  cannot reach another environment. Only a SHA-256 hash + a non-secret lookup prefix are stored; the
  plaintext is returned once. Tokens expire, rotate and revoke; a best-effort background service surfaces
  ones nearing expiry. A new `Keyward.SoftwareClient` authentication scheme resolves the (tenant, project,
  environment) scope from the token record (never the request) and sets the tenant scope
  server-authoritatively, so reads run under the query filter + row-level security. New token-authenticated
  client read API (`GET /keyward/api/v1/secrets` for the IConfiguration bulk load and `/secrets/{**key}`),
  per-token rate limiting, and management endpoints to issue/list/rotate/revoke tokens. The token table is
  installation-global (looked up by prefix before the tenant is known) and holds no secret material.
- Slice 4 — tenant isolation (defense in depth): every tenant-owned table carries a denormalized
  `TenantId`; an EF Core global query filter scopes all reads to the ambient `ICurrentTenant`; SQL Server
  **row-level security** (a schemabound predicate over `SESSION_CONTEXT('TenantId')`, applied by a
  connection interceptor) enforces the same boundary inside the database as a backstop; and a central
  `IAuthorizationService` resolves a resource's true owning tenant so a "right scope, foreign project"
  attempt is denied. The host edge sets the server-authoritative scope (API route, Blazor circuit) via
  `ITenantScopeSetter`. Two-login model documented (`amkeyward_app` runtime vs `amkeyward_migrator` DDL,
  `db/setup-logins.sql` + `docs/database-logins.md`). Covered by an adversarial cross-tenant test at the
  application layer, plus an RLS test that runs against the least-privilege login when configured.
- Initial solution skeleton (Slice 0): layered projects — `Am.Keyward.Core` (pure domain/application),
  `Am.Keyward.Infrastructure`, `Am.Keyward.Contracts`, `Am.Keyward.Api`, `Am.Keyward.Ui.Blazor` (RCL),
  `Am.Keyward.Ui.Blazor.App` (standalone reference shell), and `Am.Keyward.Tests`.
- `Directory.Build.props`, MIT `LICENSE`, `SECURITY.md`, end-user `docs/`, and GitHub Actions CI
  (build + test on .NET 10 / SQL Server).
- Slice 1 — core domain model (`Am.Keyward.Core`): aggregates (tenants, global users, tenant/group
  memberships; projects → runtime environments → software secrets → per-environment values →
  versions; vaults → folders → items → versions; access grants; audit entries), value objects
  (`EncryptedValue`, `SecretKey`, `EnvironmentName`, `GrantScope`) and ports. The domain is pure (no
  EF/ASP.NET/crypto references) and guarded by a NetArchTest architecture test.
- Slice 2 (crypto) — explicit envelope encryption (`Am.Keyward.Infrastructure`): AES-256-GCM per value
  with a fresh 256-bit data key, full-slot AAD binding (`Aad`), DEK wrapping via `IKekProvider`
  (`StaticKekProvider`, AES-256-GCM wrap — BCL primitive in lieu of RFC-3394 AES-KW; recorded in
  `EncryptedValue.WrapAlg`), DEK zeroed after use. On-disk format frozen as `FormatVersion = 1`.
  Verified by round-trip, tamper-detection, slot-substitution and wrong-KEK tests.
- Slice 2 (persistence) — EF Core 10 / **Microsoft SQL Server**: `KeywardDbContext` (default schema
  `amkeyward`, schema-scoped migrations history), value conversions for `EncryptedValue` / `SecretKey` /
  `EnvironmentName`, the Initial migration and a design-time factory.
- Slice 3 (walking skeleton, core) — software-credentials vertical: `ISoftwareSecretService` (Core
  application) with an EF-backed implementation (encrypt-and-store / read-and-decrypt, full-slot AAD), a
  minimal per-tenant hash-chained `DbAuditSink`, and the `AddKeyward` DI registration. Proven by an
  end-to-end integration test (DI → SQL Server → encrypt/store → read/decrypt; value encrypted at rest;
  operations audited).
- Slice 3 (walking skeleton, hosting) — `Am.Keyward.Api` (`MapKeywardApi`, versioned under
  `/keyward/api/v1`; unauthenticated for now — token auth lands in a later slice) and the standalone
  reference shell wired up: `AddKeyward`, startup migrate + demo tenant/project seed, a dev KEK loaded
  from a local key file outside the database, and a `/secrets` Blazor page. Verified end-to-end over
  HTTP against SQL Server (store → encrypted at rest → read).

### Changed

- The Keyward feature UI is **embeddable**: the routable pages plus the `VaultWorkspace` component, the
  `SharedResource` localizer and all `.resx`, and the `EdgePasswordCsv` importer live in the reusable RCL
  `Am.Keyward.Ui.Blazor`. The pages don't depend on the shell's demo seed or ASP.NET Identity: they read the
  actor from the `ICurrentUser` port and the active tenant/project from a host-supplied
  `IKeywardWorkspaceContext` seam (the reference shell implements it via `DemoWorkspaceContext`). A host
  embeds the pages by referencing the RCL, registering an `IKeywardWorkspaceContext`, and adding the RCL
  assembly to `MapRazorComponents<App>().AddAdditionalAssemblies(...)` and the router. The standalone shell
  keeps the host concerns (App/Routes, layout, account, home/not-found/error).
- The embedded feature pages sit under an **`/amkeyward` route prefix** (`/amkeyward/secrets`,
  `/amkeyward/vaults/personal`, `/amkeyward/vaults/team`, `/amkeyward/tokens`, `/amkeyward/vaults`) so they
  cannot collide with a host app's own routes — mirroring the `/keyward/api/v1` and
  `_content/Am.Keyward.Ui.Blazor/` namespaces. Links/navigation use the `KeywardRoutes` constants.

### Fixed

- Software-client tokens encoded their prefix/secret as Base64Url, whose alphabet includes the `_`
  separator; a token whose random secret contained `_` failed to parse and was rejected at authentication
  (intermittent). Token segments are now lowercase hex, so parsing is deterministic. Added a many-sample
  parse regression test.
- Storing a second per-environment value for an existing software secret failed with a 0-row
  `DbUpdateConcurrencyException`: because entity keys are app-assigned GUIDs, EF Core's graph state
  heuristic mis-marked the brand-new child as `Modified` (a 0-row `UPDATE`) instead of `Added`.
  New `SecretValue` / `SecretVersion` children are now marked `Added` explicitly. Covered by a
  regression test that stores the same key in two environments.
