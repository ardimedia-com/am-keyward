# Security Policy

AM KEYWARD is a credential & secrets manager in **early development (pre-1.0)**. Its design has **not**
yet undergone an external security review — no independent party has audited the envelope crypto, the tenant
isolation or the audit hash chain. It is usable with real secrets, but that assurance gap is real: everything
in this policy rests on the project's own testing and internal reviews (the latest, a code-level review in
November 2026, found no cross-tenant path and no flaw in the envelope encryption; its findings are fixed in the
release after 0.38.0-preview). Weigh it against what the secrets protect, and track releases so you get fixes.

## Reporting a vulnerability

Please report security issues **privately** — do **not** open a public GitHub issue.

- Email: **harry@ardimedia.com**

Include affected version/commit, a description, and reproduction steps. We will acknowledge and work
with you on a coordinated disclosure.

## What the design provides

See the [README threat model](README.md#threat-model-summary) for the full picture. In brief, AM KEYWARD
ships: envelope encryption with an **external KEK** (never in the DB) and slot-binding AAD; defense-in-depth
**tenant isolation** (query filter + server-authoritative tenant + SQL Server row-level security +
least-privilege runtime login); a **tamper-evident audit hash chain** with an out-of-band checkpoint;
**DSGVO crypto-shredding** of actor PII (erase destroys a per-subject key, the immutable chain keeps the
pseudonym); **dual-control break-glass** with a non-repudiable out-of-band trail; **telemetry redaction** of
the encrypted envelope; **rate-limiting/lockout** and env-scoped, hashed, rotatable software-client tokens;
and a **KEK-integrity** backup/restore check plus health endpoints. Operational procedures are in the
[operations & KEK/DR runbook](docs/operations-runbook.md).

## AI agents (agent tokens)

An agent token lets an AI assistant act for the user who issued it. The threats this design addresses, and the
ones it leaves to the operator and the user:

- **A value leaking into the assistant's context.** Values are write-only: no agent endpoint returns a stored value
  or a part of it — for applications not at all, for vault entries only after a per-request human approval, and then
  to the Windows or macOS clipboard, not to the assistant. The clipboard is cleared after 30 seconds or when the MCP
  server stops; a server that is killed cannot clear it, and on macOS a clipboard history may record the value.
  Tests check every response and the host's log output for values.
- **A disguised reveal request.** The approval shows the entry's name at request time and, if the agent renamed the
  entry, its earlier name; a later change is flagged, and the agent's own rename voids its pending requests. A token
  may hold at most 3 undecided requests.
- **Text from KEYWARD steering the assistant.** Entry, vault and folder names and notes reach the assistant on one
  line between ⟦ and ⟧, with control characters removed, and the tool descriptions state that such text is data.
- **An assistant told to exfiltrate or plant data (prompt injection).** The token reaches only what it was given:
  allowlisted vaults opened to agents, allowlisted applications and the ones it created, with the ticked
  permissions. It cannot read a software secret, cannot issue or see an app token, and may rename or delete only its
  own still-empty placeholders — it cannot break a key a program already reads. A value it sets is visible to the
  person in the UI and audited as the agent. Treat an agent's reveal reason as untrusted text.
- **A stolen agent token.** Hashed at rest, always expiring (≤ 365 days), revocable, rate-limited, throttled on
  failed authentication, re-checked against the user and their role on every request, and restrictable to
  networks. Junk tokens from one address cannot lock out a valid token; refused tokens are audited (never the token
  itself). The MCP server sends a token only to the https address it was stored for, and reads that address only
  from `Keyward__ServiceUri`. **Operator:** expose `/keyward/api/v1/agent` only to internal networks
  (`AllowedNetworks`), list your reverse proxy in the forwarded-headers configuration and make sure its address is
  never among the allowed networks; keep the token in the Windows Credential Manager or macOS Keychain, not in files
  (on Linux `KEYWARD_AGENT_TOKEN` is not bound to an address).
- **A stolen app (software-client) token.** Hashed at rest, environment-scoped, rotatable, rate-limited, throttled on
  failed authentication. **Operator:** set `Keyward:Client:AllowedNetworks` to the networks of the deployed
  applications, so a leaked token is useless from anywhere else (without it the host logs a startup warning).
- **Lost updates.** Every change to an existing value needs the version the agent saw (`If-Match`); a concurrent
  change answers 412.

## Operator responsibility

AM KEYWARD is self-hosted and library-first; the **operator** is responsible for the security of their
deployment, including:

- **KEK custody** — the key-encryption-key is **never** stored in the database. Keep it in a separate
  store (e.g. Azure Key Vault / HSM / a protected key file) and **verify your KEK restore works** —
  **KEK loss = total, unrecoverable data loss**.
- Database security. Tenant row-level security is enforced against **every** principal, including
  `db_owner`, so it does not depend on your choice of login. A least-privilege runtime login
  (`amkeyward_app` for runtime, `amkeyward_migrator` for migrations) additionally withholds the right to
  *disable* the policy or change the schema — recommended hardening where it is practical. See
  [docs/database-logins.md](docs/database-logins.md).
- Network exposure, rate limiting, TLS, and general hardening.
- Backups of the database and the KEK store (on separate schedules/locations), the correct **restore
  order** (KEK store before database), and a **rehearsed KEK restore drill** — see the
  [operations runbook](docs/operations-runbook.md).
- The out-of-band **break-glass trail** (`Keyward:BreakGlass:SinkFilePath`, required outside Development) on
  storage the database admin cannot rewrite, the audit-chain anchors next to it, and monitoring the `/health`
  endpoints and the ops-monitor warnings.
- **One instance per database.** Background jobs are not coordinated across processes; a second instance reports
  Unhealthy.
- For the reference shell: an explicit environment, `Keyward:PublicBaseUrl` (https), `AllowedHosts` set to your host
  name, invite-only registration (the default), and the security headers it sends — custom pages must not use inline
  scripts or `onclick=` handlers.

## No warranty

Provided "as is" under the [MIT license](LICENSE), without warranty of any kind.
