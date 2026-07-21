# Changelog

All notable changes to this project are documented here, following
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The project is pre-1.0.

## [Unreleased]

### Changed

- **Vault «Einträge» tab is a two-pane master-detail.** The entry list stays on the left; the right pane
  shows the selected entry's detail — with edit/delete in its header and deliberately **no close button**
  (clicking another entry simply replaces the pane). «Eintrag hinzufügen» moved from a collapsed accordion
  above the list to a button at the pane's top right that opens the add form in the pane. Deep links and
  search hits open their entry in the same pane. Stacks vertically on narrow viewports.

- **Tab bar renders as a bordered tab area.** `KeywardTabBar` gains a `ChildContent` mode: bar + the active
  tab's content framed by ONE border and radius (mirrors am.ui's `AmTabArea`, which this package cannot
  reference) — the segmented bar keeps its muted-pill styling. The vault pages («Einträge» /
  «Tresor-Einstellungen») and the applications page («Umgebungen» / «Applikations-Einstellungen») use it;
  a read-only applications view (no tab bar) keeps its unframed layout. Without `ChildContent` the bare
  bar renders as before.

### Added

- **Break-glass UI (`/amkeyward/breakglass`) — the dual-control emergency access is now operable.** A new
  System-Admin-only page drives the full flow: request access to a team vault with a mandatory reason, a
  **different** admin approves or rejects (self-approval is blocked and labeled), and the requester (or
  approver) consumes the approved request within its validity window. New service surface:
  `IBreakGlassService.IsSystemAdminAsync` (UI gating), `ListTargetVaultsAsync` (team-vault picker — metadata
  only, the one place an admin sees vaults they hold no grant on), and `ListGrantsAsync` (history with display
  names resolved). Localized in all six languages; the reference shell links the page in its admin section
  (embedded hosts place it in their own admin nav, like Groups).

### Changed

- **BREAKING: consuming a break-glass grant now materializes real access.** `ConsumeAsync` creates a regular
  **Manage** access grant for the *requester* on the target resource (upserting a lower existing grant) —
  visible in the vault's sharing list, enforced by the existing ACL checks, and revocable after the recovery.
  Previously consumption only recorded the event without granting anything. Consumption now requires a
  tenant-scoped target (personal vaults stay out of break-glass scope by design) and throws
  `InvalidOperationException` for a tenant-less one. Consumers of `IBreakGlassService` must implement the
  three new interface members.

- **Shareable deep link per vault item.** Every vault entry now has a short, stable URL
  (`/amkeyward/e/{code}`) you can paste into documentation. Opening an entry reflects it in the address bar,
  and a **"Link kopieren"** button in the detail pane copies the absolute link (a toast confirms). The `code`
  is the item's public id as **Base62** (22 chars, no hyphens/underscores), so a double-click selects the
  whole id when copying. The `EntryLink` resolver page forwards a link to the right vault page with the entry
  opened; an unknown, malformed, or inaccessible link falls back to the vault list rather than erroring (no
  existence leak). The public id is **separate from the item's crypto-bound primary key and survives a
  cross-vault move** (which mints a new key by re-encrypting) — so a documentation link keeps working after the
  entry is moved between vaults. Requires the `VaultItemPublicId` migration (adds a unique `PublicId` column;
  existing rows are back-filled with distinct values).

- **Tabbed detail pane (`KeywardTabBar`).** The vault pages (personal/team) and the applications page now
  group the right-hand detail into tabs instead of a stack of accordion areas — the left-hand list is
  unchanged. Vaults: **«Einträge»** (add entry + item list) and **«Tresor-Einstellungen»** (manage / share /
  folders / import / export). Applications: **«Umgebungen»** (add + quick-hops + list) and, for managers,
  **«Applikations-Einstellungen»**. `KeywardTabBar` is a reusable BlazorBlueprint-styled tab bar. The Secrets
  and Client-Tokens pages keep their single add-and-list layout (no second group to tab).

- **Transient-notification port `IKeywardNotifier`** (`Success`/`Error`/`Info`). Keyward's UI notifications
  ("Vault created", "Moved", errors) go through this port instead of an inline status bar. Standalone, the
  built-in `KeywardToastHost` renders a BlazorBlueprint-styled, auto-dismissing toast (bottom-right, per-kind
  accent); a host overrides `IKeywardNotifier` (registered with `TryAdd`) to route them onto its own toasts —
  e.g. BlazorBlueprint's `BbToast`. Vault **success** feedback now shows as a toast; the inline `.notice` bar
  is reserved for **errors**. See the new "UI design principle" section in the README.

### Changed

- **Vault search field: dropped the leading magnifier icon; the clear (×) is now part of the field.** The
  global vault search on the personal and team vault pages (`VaultWorkspace`) no longer shows a leading
  magnifying-glass icon, and its clear button sits flush at the **end of the input inside the single field
  border** (the input fills the width) instead of as a separate element. Cosmetic only.

- **Clearer, throttled "database unreachable" logging in the ops monitor.** When Keyward is enabled but its
  database cannot be reached (e.g. the `Keyward` connection string is not provisioned for the environment, or
  the `amkeyward_app` login / `amkeyward` schema does not exist yet), `OpsMonitorBackgroundService` now logs a
  single actionable warning naming exactly what to check — instead of a raw `SqlException` stack every hour. It
  stays quiet on the recurring interval until the connection recovers (then logs a one-line "reachable again").
  Genuine, non-database failures still log as an error. `DbException` is treated as an operator/config gap, not
  an internal fault.

## [0.2.1-preview] - 2026-07-14

### Added

- **`KeywardSchemaMigrator.MigrateAsync(connectionString)`** — a reusable helper to apply the `amkeyward`
  schema migrations through a caller-supplied **privileged** connection, so an embedding host no longer has to
  hand-build a `KeywardDbContext` to migrate. This supports the two-login model where the least-privilege
  runtime login cannot DDL: the host migrates via a DDL-capable connection (a dedicated migrator login, or —
  when the schema is embedded in the host's own database — the host's existing privileged connection), while
  runtime queries keep using the least-privilege login with row-level security enforced. Same EF migrations as
  `KeywardDbContext.Database.Migrate()`; idempotent. The design-time factory and the migrator now share one
  internal `NoScope` (no behaviour change to design-time tooling).

## [0.2.0-preview] - 2026-07-07

### Added

- **Localized e-mails (six languages).** Account e-mails (password reset, e-mail confirmation) render in the
  **request culture** — the language the user is viewing the UI in — via `IStringLocalizer<SharedResource>`;
  the background token-expiry notification, which has no request to follow, uses a configured language
  (`KeywardUiOptions.NotificationLanguage` / `Keyward:NotificationLanguage`, English fallback). Subject,
  card header, body, button and footer are all localized (en/de/fr/it/es/pt).
- **Expiry mails link to the app-tokens page.** New optional `KeywardUiOptions.PublicBaseUrl` (shell config
  `Keyward:PublicBaseUrl`): when set, the token-expiry notification carries an "Open app tokens" button
  with an absolute link; without it the mail stays link-free (background jobs have no request to derive a
  URL from).
- **E-mail notifications for expiring app tokens.** A background job checks hourly and e-mails
  administrators when app tokens approach their expiry, on a fixed schedule: 30, 20 and 10 days ahead, then
  DAILY from 9 days (`TokenExpiryNoticePolicy`, unit-tested; per-token dedupe via a new
  `LastExpiryNoticeDaysLeft` column that a rotation resets, migration `TokenExpiryNotifications`).
  Recipients opt in on their **profile page** (new checkbox, visible to tenant/system admins; stored as
  `AppUser.NotifyTokenExpiry`) and must administer the token's tenant. The mail lists each due token with
  its application, environment and expiry date, in the branded card layout via SMTP or maildrop
  (`IAccountEmailSender.SendAsync`); a token is only marked notified after at least one mail went out.

- **Default environments are database-backed and editable under Administration.** New page "Default
  environments" (sidebar, next to Users/Groups): the environment set every NEW application starts with. A
  tenant without custom rows shows the built-in set (Development/Test/Preview/Production) read-only;
  "Customize" copies it into editable rows (add/rename/delete, tenant-admin gated, audited), and removing
  all rows deliberately returns to the built-in set. Existing applications are never touched. New
  `TenantDefaultEnvironments` table (unique per tenant+name, EF tenant filter + row-level security,
  migration `TenantDefaultEnvironments`); `IProjectService.CreateAsync` seeds new applications from the
  tenant's set. Integration test covers built-in → customize → trimmed set → back to built-in.

- **Color themes + dark mode.** The topbar gets a palette menu (Indigo default, Mono, Storm, Midnight,
  Pastel, Amber, Ocean) and a light/dark toggle, per the win-smtp-relay admin pattern: the choice is stored
  per browser in localStorage, applied to `<html>` before first paint (no flash) and re-applied after
  Blazor enhanced navigations (`js/keyward-theme.js`); the controls are plain onclick JS, so they work on
  every page without a circuit. Both the shell variables and the embedded RCL's `--kw-*` variables react
  to `html.dark` / `html[data-theme]` — an embedding host gets themable pages by toggling the same
  class/attribute.

- **Host-configurable product name.** New `KeywardUiOptions.ProductName` on `AddKeywardUi(...)` — shown in
  the browser tab, the sidebar brand, the Home title and the texts that mention the product (localized via
  a format placeholder). The reference shell reads `Keyward:ProductName` from configuration and names the
  demo "Beispiel AG Secrets Verwaltung".

- **Pending app tokens per environment.** Creating an application (and adding an environment) automatically
  creates one app token per environment as a **pending placeholder without a secret** — visible and named
  (`<application>-<environment>`) but unable to authenticate until its first value is minted on the
  app-tokens page ("Generate token value", with an expiry choice; shown once like any issued token).
  Deleting an environment now **deletes** its tokens along with its values (previously they were revoked) —
  they could never read anything again, and the deletion itself stays in the audit chain. The `TokenPrefix`
  unique index is filtered to minted tokens (migration `PendingAppTokens`). Integration test covers the
  create → mint → add/delete-environment lifecycle.

- **Applications as a first-class UI concept.** The domain always scoped software secrets, environments and
  client tokens to a `Project` — the UI now surfaces it (labelled "Application"): a new **Applications**
  page (master-detail) creates, renames and deletes applications (delete confirms and cascades environments,
  secrets and tokens; create seeds the default environment set), and manages **each application's own
  environments** (the standalone Environments admin page moved here, since environments were always
  per-project). The Software-Secrets and Client-Tokens pages get the application as the top level of their
  left tree; the selection is remembered across pages (new circuit-scoped `KeywardUiState`, registered via
  `AddKeywardUi()`). The token name suggestion becomes `<application>-<environment>-`. One application per
  deployed piece of software makes least-privilege the visible default: a token can never read another
  application's secrets. New `IProjectService` (list/create/rename/delete, tenant-admin gated, audited) with
  integration tests. **Breaking (embedding):** `IKeywardWorkspaceContext.ProjectId` is gone — hosts supply
  only the tenant; the application is chosen inside the UI.

- **Client-token lifecycle: reactivate and delete.** A revoked token can be reactivated — its existing
  secret authenticates again, with the expiry date untouched (an expired one stays expired until rotated) —
  and any token can be permanently deleted after a confirmation. Both actions are audited (reactivate as
  Grant, delete as Delete) and covered by an integration test.
- **Tokens show their environment.** The token list and the detail card now display the environment a token
  is bound to (badge in the list, field in the detail grid), and the issue form pre-fills the token name
  with an `<environment>-` prefix that follows the environment selection until you type your own name. The
  name/note edit fields moved from the bottom of the detail card into its header, where the title was.

- **User-friendly UI rework** (navigation + the overloaded vault page), following the win-smtp-relay admin
  patterns. Navigation: grouped sidebar sections ("Vaults" / "Software") with inline SVG icons (new
  `KeywardIcon`, Lucide outlines, zero dependencies); the Home page is now a dashboard of explanatory tiles
  (icon + name + one-line purpose per section). Vaults: the single five-card page became a **master-detail
  workspace** — a tree of vaults and their folders (with item counts and a compact create field) on the
  left, and on the right either the item list (password-manager-style rows: type icon, name, folder, type
  badge) or one item's detail as a **two-column field grid with copy-to-clipboard and reveal/hide buttons**,
  like a browser password manager. A lone vault opens automatically; adding an item preselects the folder
  chosen in the tree. Folders, CSV import, sharing and vault settings (rename + danger-zone delete) live in
  collapsible sections with their explanations inside; deleting an item asks for confirmation. Tokens: the
  issue form opens on demand instead of always occupying the top of the page. All long page intros were
  shortened to one line with the full explanation behind a localized "How does this work?" expander (the
  previous texts were kept, moved to `Page.*.Help`). Item types and share permissions show localized labels.
  Localized in all six UI languages.

- **Branded HTML account e-mails.** Password-reset and e-mail-confirmation mails now render in the shared
  Ardimedia card layout (light page, white card, "AM KEYWARD · Ardimedia" header, bold title, a "bulletproof"
  CTA button with a plain-text link fallback, muted footer) with a plain-text alternative from the same
  source, so HTML and text can't drift apart. Table layout + inline CSS + no images for mail-client safety
  (incl. Outlook Classic), a print stylesheet for A4, and body/footer sizes per `email-typography.md`. The
  SMTP sender ships `multipart/alternative`; the reference maildrop sender writes the card as an openable
  `.html` next to the `.txt`. Self-contained port of the amvs `Am.App.MessageTemplates` card (that library is
  on the private feed and can't be referenced from this public repo).
- **Resend the e-mail-confirmation link from the sign-in page.** Signing in with the right password on an
  unconfirmed account previously just showed "invalid" with no way forward. Now it re-sends the confirmation
  link and says the account isn't confirmed yet. It is gated on the **correct password** (a wrong password
  still gets the same generic message), so it can neither enumerate addresses nor spam arbitrary inboxes — per
  the auth policy. A transient delivery failure is logged, not surfaced.
- **SMTP delivery for account e-mails** (password reset, e-mail confirmation) via MailKit. When
  `AccountEmail:Smtp:Host` is configured the shell sends real e-mail (relay/port/from tunable); otherwise it
  keeps dropping mail to the local `maildrop` folder. Machine-local settings go in a gitignored
  `appsettings.Local.json` (loaded optionally at startup, never committed) — see the new
  `appsettings.Local.example.json` template; pick the relay per LAN/environment per `smtp-relay-hosts.md`.

- **Folder hierarchy (subfolders).** Folders can now nest (new `ParentFolderId`, migration
  `FolderHierarchy`); the tree shows them properly indented per level, creating a folder while one is
  selected creates a subfolder inside it, and deleting a folder moves its child folders AND items up to
  its parent instead of dumping them at the vault root. A parent from another vault is refused. Covered by
  an integration test.
- **Selection-dependent work areas.** What the right pane shows follows the tree selection, always ending
  with the selection's items (title + filter pinned, rows scroll). Vault node: collapsed areas — vault
  settings (and sharing for team vaults), folders (create at root), import, add entry (two-column grid,
  like the detail view) — followed by the vault's root items; a folder behaves like a vault of its own:
  "Folder properties" (rename, create a subfolder, delete with contents moving up), import, add-entry, then
  its items. Vault-level areas never appear under an item's detail or edit view.
- **Move items between folders and vaults — including drag & drop and multi-select.** An item's detail view
  has a "Move to" panel (target vault + target folder); in the list, rows can simply be dragged onto a
  folder or vault node in the tree (the target highlights). Several items at once: Ctrl+click toggles a
  row's selection, Shift+click selects a range — a bulk bar above the list then moves the whole selection,
  and dragging any selected row takes the selection along.
  Within a vault a move is a folder change; across vaults the service decrypts and re-encrypts the content
  under the target vault's cryptographic binding (new item id there, removed from the source) — new
  `IVaultService.MoveItemAsync`/`MoveItemsAsync` (a batch is one atomic SaveChanges), audited on both sides
  and covered by integration tests. **Folders move the same way**: drag a folder in the tree onto another
  folder (it becomes a subfolder) or onto a vault (to its root — another vault takes the whole subtree
  along, folders recreated and every contained item re-encrypted, in one atomic save). A folder can never
  be moved into itself or one of its descendants (`IVaultService.MoveFolderAsync`).
- **Pinned chrome while scrolling.** The sidebar, top bar, page title/description and the global search box
  stay visible; on the vault pages the tree and the content pane scroll independently, and inside the item
  list the heading + filter box stay pinned while only the rows scroll (small screens fall back to normal
  page scrolling).
- **Search across all vaults.** A search box above the vault workspace (personal and team pages) finds
  items in every vault the user can read, matching any field: the item name and the decrypted content —
  login URL, username and note, or the value of the other item types. Login **passwords are deliberately
  never matched** (standard password-manager behavior; the result list says so). Matching happens
  server-side in `IVaultService.SearchItemsAsync` (content is encrypted at rest), debounced in the UI;
  results show the vault and the matched field, and open the item on click. One audit entry per executed
  search instead of one per decrypted item. Covered by an integration test (matches by username/value/name
  across two vaults, never by password).
- **Vault export (browser-compatible CSV).** A vault's LOGIN items can be exported as an Edge/Chrome-
  compatible CSV (`name,url,username,password,note`) and re-imported here or into a browser — the writer
  and parser share one format definition (`EdgePasswordCsv`, moved to Core, round-trip covered by an
  integration test including quoting). Personal vaults: the owner exports; **team vaults: tenant admins
  only** (a Manage grant is deliberately not enough) — enforced server-side and covered by a test. The UI
  warns that the file contains plain-text passwords; one audit event per export. Download works without
  any JavaScript (data-URL anchor).
- **Software credentials and client tokens as master-detail.** Both pages now follow the vault pattern:
  the keys/tokens as a selection list on the left, the selected entry's details on the right (secrets: the
  per-environment value table with reveal; tokens: prefix/created/expires/note as a field grid with
  rotate/revoke and inline rename) plus a collapsed "add"/"issue" area. Deleting a credential and revoking
  a token now ask for confirmation.
- **Groups: share a vault once with "IT" instead of each person.** New tenant groups (page "Groups" under
  the Administration nav section, after Users; same master-detail pattern as the vaults — groups as a tree
  on the left, the selected group's areas on the right: group settings, add member, then the member list):
  tenant admins create/rename/delete groups; members are managed by tenant admins or the group's own
  admins (role member / group admin). The team-vault "Share" area now offers **people and
  groups** as principals, shows who holds which grant (group shares are badged) and can **revoke** any
  grant. Authorization and the shared-vault list honor group grants (a member sees and reads a vault shared
  with their group; leaving the group or revoking the grant takes it away). New tables `UserGroups` /
  `GroupMemberships` (tenant-scoped: query filter + row-level security, migration `Groups`), new
  `IGroupService`, `ShareWithGroupAsync`/`RevokeShareAsync`; every mutation audited; covered by integration
  tests (access via group until revoked; lifecycle restricted to tenant admins).
- **Vault guidance for first-time users.** With no vault selected, the workspace explains why a vault gets a
  name and when several vaults make sense (with concrete examples), offers clickable name suggestions
  (Private/Work/Family/Banking; IT/Accounting/Infrastructure/Customers for team vaults) that prefill the
  create field, and — when no vault exists yet — a one-click default vault. The Home dashboard is grouped
  into two labelled sections (vaults for people / software credentials for applications), two example-rich
  tiles per row.

- **Tenant-role management and account deletion in the admin area.** The user administration
  (`/account/admin/users`, system admins only) now shows each account's tenant role (member / tenant admin)
  and can promote or demote it; the last tenant admin can never be demoted (guarded in the UI and
  server-side). Accounts can be **deleted** (offboarding) after an inline confirmation: the Identity login,
  tenant memberships, access grants and personal vaults are removed — never yourself, never the last tenant
  admin, never the last system admin; the domain user row is kept so the audit chain's actor references stay
  intact. Administration is also reachable from the left navigation (a new "Administration" group, visible
  to system admins only). Every action is audited.

### Changed

- **Account e-mails carry the configured product name.** Password-reset, e-mail-confirmation and the
  token-expiry notification now use `KeywardUiOptions.ProductName` in the subject, the card header and the
  body texts (previously hardcoded "AM KEYWARD").

- The freshly issued/rotated token value is now strictly one-time per page visit: any navigation (or
  switching the application) discards it — previously it could still be on screen after leaving the
  app-tokens page and returning.
- The app-token list is sorted by name (it was newest-first), matching applications, environments and
  secrets, which were already alphabetical.

- **"Add secret" no longer silently upserts an existing key.** Creating a secret whose key already exists
  now shows "the key already exists — select it on the left" instead of writing a new value version to the
  existing key (changing an existing key's values is the per-environment table's job). The add area's
  feedback ("Secret … created." / duplicate warning) now appears inside that area instead of below the
  detail card.

- **Larger action buttons** (shell + embedded UI) for a friendlier, easier-to-hit look; the compact
  `btn-sm` inline actions grew slightly too.
- **User-focused Home tagline** in all six languages (what the product does for its users, in three
  sentences) instead of the technical "open-source, .NET-native …" line.
- The topbar user menu no longer duplicates the "Users" administration link — user administration lives
  only in the sidebar's Administration group.

- **App-token names are unique per application** (on issue and on rename), so tokens stay identifiable in
  lists and audits. Multiple tokens per (application, environment) remain deliberately allowed — one per
  deployed host, or an overlap token during a zero-downtime swap — they just need distinct names.
- **App-token names are auto-assigned by default.** The name field on the issue form is optional: left
  empty, the server names the token `<application>-<environment>` (numbered `-2`, `-3`, … when taken); a
  custom name (e.g. a host/purpose suffix) stays possible. The environment badge was dropped from the token
  list and detail header — the environment is in the name and in the detail's Environment field anyway.

- **UI rename: "Client tokens" → "App tokens"** in all six languages, matching the new Applications concept
  (a token always belongs to one application). Routes, resource keys and code identifiers
  (`SoftwareClientToken` etc.) are unchanged.

- Team-vault naming guidance now also shows **function/task-based vaults** ("Online orders", "Contracts")
  alongside the team/department, customer/project and infrastructure examples — with matching suggestion
  chips (all six languages).

- Account-e-mail subject/content is now defined once (`AccountEmailMessages`) and shared by both the SMTP and
  maildrop senders, so every transport renders the identical message.

- **Admin-definable environments.** A project's environments are no longer a fixed set: they have their own
  "Environments" page in the Administration nav section (next to Users and Groups) — everyone can see them,
  tenant admins (and system admins) manage them: **add, rename and delete** (delete asks for confirmation;
  it removes the environment's secret values and its app tokens (initially revoked; later changed to
  delete, see the pending-app-tokens entry) — values and tokens bind by id,
  so a rename follows automatically everywhere; the project's last environment cannot be deleted). New
  `ISoftwareSecretService` methods `ListEnvironmentsAsync`/`AddEnvironmentAsync`/`RenameEnvironmentAsync`/
  `DeleteEnvironmentAsync`, all audited and covered by an integration test. The environment selects for
  secrets AND client tokens are sourced from the project's live list instead of being hardcoded; new
  environments appear immediately in every secret's value table.
- **"Software credentials" renamed to "Software secrets"** (all six languages, including every text that
  referenced the section) — the values are secret configuration values per environment (API keys,
  connection strings, signing keys), not only credentials; the domain model already called them
  `SoftwareSecret`. Routes and code identifiers are unchanged.
- **Client-token usability.** The expiry when issuing is now a choice (1/10/30/60/90/180/360 days or
  never, default 90); the "Prefix" field is labelled "Identifier (token start)" — it is the token's visible
  beginning for recognizing which token is configured where, not a second credential. The secrets value
  table gained a per-environment reveal eye (in addition to the all-values toggle) and the current/new
  value columns now share the full available width.

### Fixed

- **Deleting a vault now deletes its items and their encrypted versions** (new
  `FK_VaultItems_Vaults_VaultId` cascade, migration `VaultItemCascadeAndNameConstraints`) — previously
  `VaultItems` had no foreign key, so a vault or account deletion left the items' ciphertext orphaned in
  the database forever (invisible to every query, but retained). The migration also removes any existing
  orphaned item rows. Found in the 2026-07-07 deep review.
- **Race-proof name uniqueness in the database**: unique indexes on `Projects(TenantId, Name)` and
  `SoftwareClientTokens(TenantId, ProjectId, Name)` back the application-level checks (same migration;
  pre-existing duplicates are suffixed `-dupN`).
- **Embedding no longer requires host localization setup**: `AddKeywardUi()` registers `AddLocalization()`
  itself and the RCL carries a `ResourceLocation` assembly attribute, so the Keyward strings resolve
  regardless of the host's `ResourcesPath` (previously a foreign host crashed without `AddLocalization`
  and showed raw resource keys without `ResourcesPath = "Resources"`).
- **Token-expiry mails are per-tenant isolated**: one failing tenant no longer aborts the run for the
  remaining tenants, and the dedupe marks are saved per tenant — previously a failure after a successful
  send could re-send identical notices on the next run.
- **Bulk credential deletion is fully audited**: deleting an application or an environment now writes one
  audit entry per removed app token (plus the project/environment entry), keeping the per-token lifecycle
  trail complete.
- Rolling back the `PendingAppTokens` migration no longer fails when pending placeholders exist; switching
  applications on the app-tokens page no longer briefly shows the previous application's tokens.
- Documentation corrected against the code (2026-07-07 deep review): README embedding guide rewritten as a
  complete, verified checklist (prerequisites incl. `AddCascadingAuthenticationState`/`AuthorizeRouteView`,
  domain-data bootstrap of Tenant/AppUser/TenantMembership, tenant circuit handler, `MapKeywardClientApi` +
  `UseRateLimiter`, `MapKeywardApi`, antiforgery-after-auth order, `.kw-fill` host CSS, published preview
  packages instead of "no packages yet", `Am.Keyward.AspNetCore` in the reference list); the
  software-client API doc gained the token lifecycle (pending placeholders, auto-names, uniqueness,
  reactivate/delete, rotation window restart, expiry e-mails) and dropped the stale "no tenant membership
  check" warning; the runbook no longer promises an unimplemented 90-day vault retention and reflects the
  system-read bypass; the database-logins doc reflects the self-provisioning test setup.

- **Rotating an (expired) token now actually renews it.** Rotation previously replaced only the secret and
  kept the old absolute expiry — rotating an expired token produced a new token that was dead on arrival,
  and the Created date never changed. Rotation now restarts the validity window: Created becomes the
  rotation time and, unless a new expiry is passed, the ORIGINAL lifetime is re-applied from now (a 10-day
  token becomes a fresh 10-day token; a never-expiring one stays never-expiring). Covered by an integration
  test.
- **Antiforgery failure on admin form posts.** `app.UseAntiforgery()` ran before
  `UseAuthentication`/`UseAuthorization`, binding every antiforgery token to the anonymous user; the first
  form POST on an authenticated page (e.g. disabling a user) then failed with "the provided antiforgery
  token was meant for a different claims-based user". The middleware now runs after authentication, as the
  framework requires. Anonymous account pages (login/register) never tripped it, which is why it went
  unnoticed.
- **Permanent horizontal + vertical scrollbars.** The shell was missing a global `box-sizing: border-box`,
  so the content area (`width:100%` plus padding) grew slightly beyond the viewport on every page.
- **Vault share candidates are scoped to tenant members.** The "share with user" dropdown listed every
  installation-global user — including test residue and, in a shared installation, other tenants' users.
  Candidates now come from explicit `TenantMemberships`; the reference shell ensures a demo-tenant
  membership for each UI user at sign-in (existing users are backfilled on their next sign-in).
- **Integration tests use their own database.** The tests ran against the app's dev database (`amkeyward`)
  and polluted it with hundreds of seeded test users; they now target a dedicated `amkeywardtest` database
  (locally and in CI), and the login-provisioning script targets the test database taken from the
  connection string instead of a hardcoded name.

## [0.1.1-preview] - 2026-07-06

### Added

- **New `Am.Keyward.AspNetCore` hosting-glue package** so an embedding host no longer copy-pastes the
  wiring from the reference shell. It provides `KeywardClaims` (the `keyward:user_id` /
  `keyward:is_system_admin` claim names, one source of truth), `app.UseKeywardCurrentUser()` (HTTP middleware
  that establishes the server-authoritative current user from the principal) and `AddKeywardBlazorUserScope()`
  (the Blazor Server circuit-handler counterpart). It is identity-provider-agnostic — the host's auth layer
  stamps the claims (ASP.NET Identity, external OIDC, ...), this package consumes them — so it forces no
  ASP.NET Core Identity dependency. Tenant selection stays the host's own concern. The reference shell now
  consumes the package instead of hand-rolling the middleware and per-circuit user handler.
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

- **`AddKeywardSoftwareClientApi` now registers the read API's per-token rate-limiter policy itself**, so a
  host can call `MapKeywardClientApi()` without hand-registering the `keyward-software-client` limiter (which
  the endpoint requires — previously a runtime footgun for embedders). It composes with any limiter the host
  registers, and the limits are tunable via an options lambda; the host still adds `app.UseRateLimiter()`. The
  reference shell dropped its ~20 lines of limiter wiring.
- **CI now runs the integration/isolation tests against a real SQL Server.** A new `integration-tests.yml`
  workflow stands up a SQL Server service container (Developer edition) on Linux, so the tenant-isolation,
  row-level-security and audit-chain guarantees are actually exercised on every push/PR — the existing
  `windows-latest` build (`ci.yml`) and the release pipeline are untouched. With `CI=true` an unreachable
  database now fails the build instead of silently skipping the integration tests.
- **Test database bootstrap is now self-contained and config-driven.** The integration tests read their
  connection string from `appsettings.json` (localhost default),
  overridable by `ConnectionStrings__Keyward` so CI can point at a SQL-auth server (password from a CI secret,
  never committed). An assembly bootstrap applies the migrations (creating the schema, no separate `dotnet ef`
  step) and provisions the least-privilege `amkeyward_app` login from `db/setup-logins.sql` with generated
  passwords — so the SQL Server row-level-security test now runs in every test run instead of being skipped
  unless an operator set `KEYWARD_APP_TEST_CONNECTION` by hand.
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
