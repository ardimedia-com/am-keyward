# Security Policy

AM KEYWARD is a credential & secrets manager in **early development (pre-1.0)**. Its design has **not**
yet undergone an external security review. Do not use it to store real secrets yet.

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

## Operator responsibility

AM KEYWARD is self-hosted and library-first; the **operator** is responsible for the security of their
deployment, including:

- **KEK custody** — the key-encryption-key is **never** stored in the database. Keep it in a separate
  store (e.g. Azure Key Vault / HSM / a protected key file) and **verify your KEK restore works** —
  **KEK loss = total, unrecoverable data loss**.
- Database security and a least-privilege runtime login — use the two-login setup (`amkeyward_app` for
  runtime, `amkeyward_migrator` for migrations) so the runtime cannot bypass tenant row-level security.
  See [docs/database-logins.md](docs/database-logins.md).
- Network exposure, rate limiting, TLS, and general hardening.
- Backups of the database and the KEK store (on separate schedules/locations), the correct **restore
  order** (KEK store before database), and a **rehearsed KEK restore drill** — see the
  [operations runbook](docs/operations-runbook.md).
- The out-of-band **break-glass trail** (`Keyward:BreakGlass:SinkFilePath`) on storage the database admin
  cannot rewrite, and monitoring the `/health` endpoints and the ops-monitor warnings.

## No warranty

Provided "as is" under the [MIT license](LICENSE), without warranty of any kind.
