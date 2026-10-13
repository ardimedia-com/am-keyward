# Keyward for agents and scripts — analysis of five extensions

Status: analysis (2026-10-13, against 0.29.0-preview); decisions T18–T27 taken on 2026-10-13 (see section 4). No code,
migration or deployment is part of it.

## Summary

Keyward already has the machine half these extensions need: **applications** (keys per environment, encrypted
values with versions), **app tokens** scoped to one application and environment, the read-only **software-client
API**, the **`Am.Keyward.Client`** package, read statistics per key and per token, heartbeat monitors, network
limits and expiry notices for values and tokens. What is missing is the last metre: a **command-line and PowerShell
surface** that lets a script or an MCP configuration read through that API instead of a plain-text file, and
**expiry and usage metadata on vault entries**, where most human-managed credentials (PATs, client secrets, portal
logins) live today.

Recommended order — security gain first:

| Phase | What | Effort | Removes |
|---|---|---|---|
| 1 | `keyward` CLI (`login`, `get`, `run`, `headers`) and a PowerShell SecretManagement vault on top | M + S | plain-text secret files, bearer tokens in MCP configs, regex parsing |
| 2 | Expiry on vault entries, one `expiring` list across everything, notices, MCP `list_expiring` | M | expiry tracking by hand |
| 3 | «Used by» on entries and keys, declared plus observed, shown on rotation | S–M | forgotten consumers after a rotation |
| 4 | Linked copies between installations — metadata first, push replication only if needed | S (L) | silent drift between installations |

The principle behind phase 1: **machines read through the software-client API with app tokens; agents never
receive values; a secret is injected into the narrowest process that needs it** — never into the agent's own process.

## 1. What exists today

| Area | What the code has | Where |
|---|---|---|
| Human vaults | personal and team vaults, entries (Login with 2FA key, note, API credential, connection string, generic), versions, folders, moves, deep links | `Core/Domain/Human.cs`, `Infrastructure/Persistence/VaultService.cs` |
| Agent API | agent token per user and computer, scopes (list, read URL/user, write, reveal request, one-time codes, manage applications), vault and application allowlists, networks, expiry and reminders | `Api/KeywardAgentApi.cs`, `Core/Domain/AgentToken.cs` |
| Values for agents | never returned; reveal needs a human approval and goes to the clipboard; one-time codes optionally direct | `RevealRequestService`, `VaultService.RevealFieldAsync`, `GenerateTotpCodeAsync` |
| Applications | applications, environments, keys (`Section:Key`), one value per environment with versions | `Core/Domain/Software.cs` |
| App tokens | one token per (application, environment), hash only, expiry (enforced), rotation, revocation, pending placeholders, note «where deployed», last access and IP | `Core/Domain/SoftwareClientToken.cs` |
| Software-client API | `GET /secrets`, `GET /secrets/{key}`, `GET /ping`; rate-limited per token; network list (`Keyward:Client:AllowedNetworks`, 0.29) | `Api/KeywardClientApi.cs` |
| Client package | `KeywardSecretsClient` (`GetAllAsync`, `GetAsync`, `PingAsync`, `Create` for hosts without DI), `AddKeywardSecrets` configuration provider, token from an environment variable by convention | `Am.Keyward.Client` |
| In-process reads | `KeywardMachineSecrets` — an embedding host reads its own secrets, Keyward first with configuration fallback | `Infrastructure/Software/KeywardMachineSecrets.cs` |
| Expiry | value: `ExpiresAt` (advisory) + rotation note + notices 30/20/10 days then daily; app tokens and agent tokens: enforced expiry + notices | `SecretValue`, `ExpiryNoticePolicy`, `*ExpiryNotificationService` |
| Observed usage | per token: daily requests, client IPs, alerts (new IP, resumed after silence), heartbeat monitor; per key and environment: last read, source, count | `TokenAccess*`, `SecretReadAccess` |
| Audit | hash-chained audit entries with actor kind (user, agent, …) and token id; bulk client read = one entry, single-key client read = statistics only | `Core/Domain/Audit.cs`, `SoftwareSecretService` |
| Local token storage | Windows Credential Manager / macOS Keychain, one entry per installation, masked input | `Mcp/CredentialStore.cs`, `Mcp/MacKeychainStore.cs` |

Two facts shape everything below:

1. **Scripts should not use the agent API at all.** The agent API acts *as a person* and deliberately never hands
   out a value — that is why reading a secret for a script «needs the reveal flow». The software-client API is the
   machine path: a token per consumer, read-only, scoped, network-limited, observable.
2. **Claude Code can keep secrets out of its configuration already**: `${VAR}` expansion in `command`, `args`,
   `env`, `url` and `headers`, and `headersHelper` — a command run at connection time whose JSON output becomes
   the request headers ([Claude Code MCP docs](https://code.claude.com/docs/en/mcp)). Keyward only has to supply
   that command.

## 2. The extensions

### 2.1 Secret injection at start (`run`, `headers`, `env`)

**Reuse.** `KeywardSecretsClient` (HTTP, token handling), the credential stores of `amkeyward-mcp` (Windows
Credential Manager, macOS Keychain), the masked token input of `amkeyward-mcp setup`, the release pipeline that
already ships `amkeyward-mcp` as a .NET tool and as single-file programs per platform.

**Missing.** A command-line program for people and scripts; a way to keep an *app* token (not an agent token) in
the operating system's store; a reference syntax; process launching.

**Design (T19 A).** A new .NET tool and single-file program **`keyward`** (`Am.Keyward.Cli`) for people, scripts
and servers; `amkeyward-mcp` stays the agents' program. The credential store moves from `Am.Keyward.Mcp` into a small
shared package, so both programs and the PowerShell vault use one implementation. Kept apart because they serve
different token kinds (an agent token acts as a person, an app token is a machine), because a server running
scheduled tasks needs no MCP server, and because every open agent session locks `amkeyward-mcp`'s files — updates of
the scripts' program must not depend on closing all agents.

| Command | Does |
|---|---|
| `keyward login <profile> --service https://keyward.example.com` | asks for an app token (masked), checks it with `/ping`, stores it as `AmKeyward:App:<host>:<profile>` |
| `keyward logout <profile>` / `keyward profiles` | removes / lists stored profiles (never values) |
| `keyward get <profile>:<key> [--json]` | prints one value to stdout — for a script that captures it |
| `keyward run --env NAME=<profile>:<key> [--env …] [--all <profile> [--prefix P_]] -- <program> [args]` | resolves the values, starts the program with them as environment variables, passes its exit code through |
| `keyward headers --set "Authorization=Bearer {<profile>:<key>}"` | prints the JSON object Claude Code's `headersHelper` expects |
| `keyward env <profile> [--shell powershell\|sh]` | prints assignments for the current shell session — least preferred, see security |

A profile is an installation plus one app token; the token already fixes application and environment, so a
reference is just `profile:key` (e.g. `ops:Prtg:ApiToken`). Values never appear on a command line.

MCP configuration examples (user scope, no secret in the file):

```json
{
  "mcpServers": {
    "mail-relay": {
      "type": "http",
      "url": "https://relay.example.com/mcp",
      "headersHelper": "keyward headers --set \"Authorization=Bearer {mcp:MailRelay:Token}\""
    },
    "some-stdio-server": {
      "type": "stdio",
      "command": "keyward",
      "args": ["run", "--env", "API_KEY=mcp:SomeService:ApiKey", "--", "some-server"]
    }
  }
}
```

**Security.**

- *Least privilege.* One Keyward application per consumer (e.g. «Workstation MCP», «PRTG checks», «Backup job»),
  holding only the keys that consumer needs; one app token per application and environment, with expiry, network
  list and a heartbeat monitor where it runs on a schedule. Revoking one token stops exactly one consumer.
- *Where plain text exists.* In the child process's environment (readable by processes of the same OS user, and
  inherited by everything the child starts), in its memory, and on stdout for `get`/`headers` (the caller decides
  where it goes). Never on disk, never in a command line, never in Keyward's logs. `keyward env` keeps values in a
  whole shell session — offered for interactive work only.
- *The launcher and agents.* `keyward run -- claude` would put the values into Claude Code's own environment, and
  any agent with a shell tool could print them: that is a reveal without approval. So: **never wrap the agent
  host**; wrap the single MCP server (stdio) or use `headersHelper` (HTTP), so only that server's process holds the
  value.
- *Same OS user.* On a workstation an agent runs as the person; whatever app token the person's scripts can use
  from the Credential Manager, the agent can use too (`keyward get`). That is acceptable for a small «workstation»
  application; unattended production scripts belong on servers under a dedicated service account, whose Credential
  Manager the interactive user (and the agent) cannot read.
- *Audit.* Today a single-key client read is recorded in the statistics, not in the audit chain. For CLI tokens a
  per-read audit entry is affordable (low volume) and worth it — see T23.
- *Revocation.* Immediate: the next `get`/`run`/`headers` fails; `headersHelper` is re-run by Claude Code on 401/403.

**Effort M.** Plus a small shared package for the credential store and one more tool and program in the release pipeline.

### 2.2 PowerShell: replace the parsing of plain-text files

**Reuse.** Everything from 2.1, plus the standard **Microsoft.PowerShell.SecretManagement** module — the documented
PowerShell mechanism for exactly this (`Get-Secret`, `Get-SecretInfo`, `-AsPlainText`, `PSCredential`), with an
extension-vault contract that a Keyward module can implement.

**Missing.** The extension vault and a convenience command.

**Design.**

```powershell
Install-Module Microsoft.PowerShell.SecretManagement, Am.Keyward.SecretManagement
Register-SecretVault -Name KeywardOps -ModuleName Am.Keyward.SecretManagement -VaultParameters @{ Profile = 'ops' }

$token = Get-Secret -Vault KeywardOps -Name 'Prtg:ApiToken' -AsPlainText
$cred  = Get-KeywardSecret -Profile ops -Name Prtg -AsCredential     # reads Prtg:Username + Prtg:Password
```

- The vault is a thin script module over `keyward get --json` (no second HTTP client, no second credential store).
- **Typed keys instead of parsing**: a credential becomes `Name:Username` / `Name:Password` / `Name:ApiToken` keys —
  the `Section:Key` form applications already use. A changed layout in a text file can no longer turn a username into
  a password.
- `-Field username|password|token` maps to those keys; `-AsCredential` builds a `PSCredential`; `-AsPlainText`
  returns a string, otherwise a `SecureString` (SecretManagement's default).
- Read-only: `Set-Secret`/`Remove-Secret` are refused (values are maintained in Keyward, by people or agents).

**Security.** As 2.1 (same tokens, same audit). No local cache by default (T22): a script run costs one HTTPS
request; a cache would be another place with plain or DPAPI-wrapped values.

**Effort S** once 2.1 exists. Migration: one application per script group, its keys filled from the old file, the
file deleted — an agent can do most of it (`create_application`, `create_secret_key`, `set_secret_value` exist).

### 2.3 Expiry dates and a list of what expires

**Reuse.** `SecretValue.ExpiresAt` + rotation note + the notice schedule (`ExpiryNoticePolicy`, dedupe per value,
reset on a new value), the token expiry services, `IKeywardAlertPresenter` (the hosts already send branded mails),
the agent API already *shows* `rotateBy`/`rotationNote` of application values.

**Missing.** Expiry on **vault entries** (where PATs, client secrets and portal logins usually are); one list across
entries, values, app tokens and agent tokens; setting the date through the agent API; MCP `list_expiring`.

**Design.**

- `VaultItem` gets `ExpiresAt` (advisory, like values), `RotationNote` and `LastExpiryNoticeDaysLeft` — clear-text
  metadata outside the encrypted content, so a list never decrypts anything. Same semantics as `SecretValue`: the
  date belongs to the current value; storing a new value resets the notices and the UI asks for the new date. One
  migration (three columns).
- `VaultItemExpiryNotificationService` on the existing schedule; recipients: the owner of a personal vault, the
  Manage holders of a team vault (T25); presenter method `NotifyVaultItemExpiryAsync` (default no-op, hosts mail).
- Agent API `GET /expiring?days=30` → rows `{ kind: VaultItem|SecretValue|AppToken|AgentToken, name, location
  (vault/folder or application/environment), expiresAt, daysLeft, rotationNote, link }`, limited to what the token
  reaches (vault scopes for entries, «manage applications» for values and app tokens, its own expiry always).
  MCP `list_expiring(days = 30)`.
- Writing: `create_login` / `create_item` / `update_item` take `expiresAt` and `rotationNote`; a new MCP tool
  `set_rotation(applicationId, key, environment, rotateBy, note)` for application values.
- A daily mail from an external worker is then unnecessary — Keyward sends the notices itself; a webhook can be
  added to the presenter later if another system must react.

**Security.** Metadata only; the list shows names and places the token can already see. Audit: changes to the date
are updates; the list is a read (one entry per call).

**Effort M** (migration, service, API, MCP, UI date field and notice texts in six languages).

### 2.4 «Used by»

**Reuse.** Observed usage already exists for application values: which app token read which key, when and from
which address (`SecretReadAccess`, token statistics, heartbeat monitors), plus the token's note «where deployed».

**Missing.** Anything for vault entries; a declared list for consumers Keyward cannot observe (a scheduled task, a
script on a server, an MCP configuration, a deployed app reading via its own configuration); a checklist at
rotation time.

**Design.**

- New table `CredentialConsumer`: target (`VaultItem` or `SoftwareSecret`), `Kind` (Server, ScheduledTask, Script,
  McpConfig, Application, Deployment, Other), `Name`, `Location` (host, path), `Link` (SR/CMDB document), `Note`,
  `CreatedAt/By`, `LastConfirmedAt`. Tenant-scoped like its target (row-level security).
- The entry shows «Used by»: the declared consumers and — for application values — the app tokens that read it
  (observed), so a migrated script appears automatically.
- At rotation (a new value), the UI shows the list as a checklist; each confirmation sets `LastConfirmedAt`. The
  agent API returns the consumers with `update_item`, so an agent rotating a credential knows what else to touch.
- MCP: `list_consumers(itemId)`, `add_consumer(itemId, kind, name, location?, link?, note?)`,
  `remove_consumer(consumerId)`; `get_item` reports the count.

**Security.** Host names and paths are internal information — readable with the entry's read scope, written with
write scope, audited. No secret is stored.

**Effort S–M.** Grows in value with 2.1/2.2: every script moved to an app token becomes observed usage.

### 2.5 Linking between installations

**Reuse.** Nothing direct: installations are independent (own key-encryption key, database, tenants, people), and
agents never carry values between them.

**Options.**

| | How | Effort | Notes |
|---|---|---|---|
| A — linked metadata | both entries carry «linked with <link of the other entry>, source of truth = A»; copying the value stays a person's act; the target shows a hint to check after a change at the source | S | no new trust between installations |
| B — one-way push | the source stores a write credential for the target (an agent token of the target installation, as an application value); «Update copy in B» (or on each new version) decrypts in the source and writes through the target's agent API (write-only, never echoed); the target entry is marked «copy of A, version n», read-only; audited on both sides | L | a standing cross-organisation data flow and one more powerful secret |
| C — no copy for machines | consumers in B read from A's software-client API with an app token of A (network-limited) | S | covers machines, not people in B |

**Security.** B creates a write path between two organisations' installations — it needs an explicit owner
decision, one direction, and an audit trail on both ends; never two-way.

**Recommendation.** A now (it ends silent drift by making the link visible), C for machine consumers, B only if more
than a handful of credentials really need to stay identical.

## 3. Phased plan

1. **Phase 1 — no more plain-text secrets (most security gain).** Extract the credential store; `keyward` (`login`,
   `get`, `run`, `headers`, `profiles`); SecretManagement vault and `Get-KeywardSecret`; per-read audit for
   CLI tokens; docs. Then migrate: one application per consumer group, scripts to `Get-Secret`, MCP configs to
   `headersHelper` / `keyward run`, delete the plain-text file. Prerequisite for the client API: set
   `Keyward:Client:AllowedNetworks` on both installations.
2. **Phase 2 — expiry.** Vault-entry expiry (migration), notices, `GET /expiring`, `list_expiring`, rotation fields
   in the agent API. Then enter the known expiry dates once.
3. **Phase 3 — «used by».** Consumers table, UI area and rotation checklist, MCP tools; observed usage from phase 1.
4. **Phase 4 — between installations.** Linked metadata (A); push replication (B) only on a later decision.

## 4. Decisions (2026-10-13)

All taken as recommended. T19 was first answered B (commands in `amkeyward-mcp`) and changed to **A** the same day,
after comparing install, update locking and server use.

| Code | Question | Options | Decision |
|---|---|---|---|
| T18 | How do scripts and MCP configurations read secrets? | A software-client API with an app token per consumer application / B a new agent-token scope «inject» / C both | **A** — the machine path exists, is scoped and observable; agent tokens act as a person |
| T19 | Where does the CLI live? | A new tool `keyward` (`Am.Keyward.Cli`), credential store shared with `amkeyward-mcp` / B more subcommands in `amkeyward-mcp` | **A** (first B, changed the same day) — separate token kinds, no MCP server on servers, updates independent of open agent sessions |
| T20 | May the launcher wrap an AI agent host (`keyward run -- claude`)? | A no — wrap single MCP servers or use `headersHelper`; documented / B allowed | **A** — otherwise the agent can print the values |
| T21 | PowerShell surface | A SecretManagement extension vault + thin `Get-KeywardSecret` / B own module only | **A** — the documented PowerShell mechanism |
| T22 | Local cache of values | A none / B DPAPI-protected cache with a short TTL | **A** — one request per run is cheap; a cache is one more copy |
| T23 | Audit of single-key reads by CLI tokens | A audit entry per read (token flag) / B statistics only, as today | **A** — low volume, high value for «who read it» |
| T24 | Expiry on vault entries | A per entry, for the current value, reset on a new value (as application values) / B per version | **A** — one semantics everywhere |
| T25 | Who gets vault-entry expiry notices? | A owner (personal) / Manage holders (team) / B a configured mailbox | **A**, B later as an addition |
| T26 | Between installations | A linked metadata now, push later only if needed / B build push replication now / C nothing | **A** |
| T27 | Where this analysis lives (public repo) | A commit it here, without internal details / B keep it in the private `.claude` folder | **A** |

### From the second pass (section 5), decided the same day

| Code | Question | Options | Decision |
|---|---|---|---|
| T28 | A credential used by machines *and* people | A one home: the application key; the vault entry only links to it / B a binding: an application key reads through to a vault-entry field / C two copies, kept in step by hand | **A**, B only on demand |
| T29 | Expiry order | A use value expiry now (machine credentials as application values), then a small agent-API phase, vault-entry expiry after / B vault-entry expiry first | **A** |
| T30 | Migrating plain-text files | A local `keyward import` with an explicit mapping file / B an agent reads the file and stores the values via MCP | **A** |

## 5. Second pass (2026-10-13) — gaps and adjustments

The design above holds after re-checking it against the code (agent API endpoints, MCP tools, client API, expiry
services) and the current Claude Code documentation. Six points sharpen it; T28–T30 above come from here.

### 5.1 One home per credential (T28)

Phase 1 moves script credentials into application keys. Many of them also exist as vault entries for people (a
monitoring login, a portal password). After the move there are two copies inside **one** installation — the same
drift problem as extension 5, just closer to home. Keyward has no link between an application key and a vault entry
today.

- **Rule (no code):** a credential has exactly one home. Read by a machine → application key. Only people → vault
  entry. Both → application key; the vault entry keeps URL and user name and links to the key («value lives in
  application X»). People with Manage rights on the application see the value there.
- **Binding (code, only if the rule proves too awkward):** an application key whose value is resolved from a
  vault-entry field at read time. It makes human vault content machine-readable, so it needs an explicit consent per
  binding by a Manage holder of the vault, an audit entry, and a visible marker on the entry. Not before there is a
  concrete case.

### 5.2 Expiry: most of it already works (T29)

`SecretValue.ExpiresAt` with the 30/20/10-day notices and the presenter mail (`SecretExpiryNotificationService`)
already covers **application values**. The credentials named as examples — personal access tokens, client secrets,
relay API keys — are machine credentials; once they are application values (phase 1 or by hand, today) their expiry is
watched without any new code.

Revised split:

- **Phase 0 (no code):** enter the known expiry dates on the application values that already exist.
- **Phase 2a (S, no migration):** agent API `GET /expiring` and MCP `list_expiring(days)` over application values,
  app tokens and agent tokens; MCP `set_rotation(applicationId, key, environment, rotateBy, note)`.
- **Phase 2b (M, migration):** vault-entry expiry as in 2.3, for what remains people-only (portal logins).

### 5.3 Migration without values in an agent's context (T30)

Section 2.2 suggests an agent does most of the migration with `set_secret_value`. That routes every value through the
model's context and the MCP transcript — exactly what Keyward otherwise avoids. Better: a local command

```
keyward import --profile-agent <host> --mapping secrets-map.json --source <plain-text secrets file> [--dry-run]
```

- The **mapping file** (no values) names, per source line or block, the target application, key and environment. An
  agent may write the mapping — it sees names and structure, the command reads the values.
- It writes through the existing agent endpoint `PUT /applications/{id}/secrets/{key}` with the agent token already in
  the credential store, so no new server surface is needed.
- `--dry-run` lists what would be written (names only) and every line it could not map; nothing is guessed — a line
  that does not match the mapping is reported, never parsed heuristically (the cause of the 401 in problem 2).

### 5.4 «Used by» shrinks once consumers read at runtime

A consumer that reads through the client API at runtime needs **no update** after a rotation — it picks up the new
value on its next read and appears in the observed usage automatically. The declared list (2.4) is only needed for
consumers that hold a **copy**: a value pasted into a third-party system, a scheduled task's stored password, a
deployed configuration that cannot read Keyward. Phase 3 therefore gets smaller with every consumer phase 1 moves, and
the rotation checklist should show observed readers as «updates itself» and only the declared ones as «to do».

### 5.5 `headersHelper` — facts that shape `keyward headers`

From the current Claude Code MCP documentation:

- runs in a shell at each connection and reconnect, **no caching**, gives up after **10 seconds**;
- re-run on **401/403**, then the call is retried once;
- helpers from a **project** `.mcp.json` run only after the trust dialog and lose environment variables whose names look
  like credentials — so Keyward-backed servers belong in the **user** scope;
- `${VAR}` expansion covers `command`, `args`, `env`, `url`, `headers` — not `headersHelper` itself.

Consequences for the CLI: `keyward headers` must answer well inside 10 s (own HTTP timeout around 5 s), write errors
to stderr only, and fail closed — if Keyward is unreachable, the MCP server does not connect, which is the right
behaviour.

### 5.6 Error contract instead of a bare 401

Problem 2 (a check failing with HTTP 401 after a format change) is as much about diagnosis as about parsing. `keyward
get` / `run` / `headers` and `Get-KeywardSecret` should fail with distinct exit codes and one-line messages: no profile
stored, token rejected or expired, network not allowed (403), key unknown, no value in this environment. A script then
fails with the reason, not with the downstream system's 401.

### 5.7 Revised order

| Phase | What | Effort |
|---|---|---|
| 0 | No code: expiry dates on existing application values; client-API network list on every installation; rule «one home» (T28) | — |
| 1 | `keyward` CLI (`login`, `get`, `run`, `headers`, `import`) + PowerShell vault, error contract, per-read audit | M + S |
| 2a | `list_expiring`, `set_rotation` over existing expiry data | S |
| 2b | Vault-entry expiry (migration) | M |
| 3 | «Used by» for copies, rotation checklist | S |
| 4 | Linked metadata between installations | S |
