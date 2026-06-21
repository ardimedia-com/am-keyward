# Changelog

All notable changes to this project are documented here, following
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The project is pre-1.0.

## [Unreleased]

### Added

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
