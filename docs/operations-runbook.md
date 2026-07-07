# AM KEYWARD — Operations & KEK/DR Runbook

Operator-facing procedures for running AM KEYWARD safely: key custody, backup/restore, rotation,
compromise response, monitoring, and break-glass. AM KEYWARD is **self-hosted and library-first** — the
operator owns and secures the deployment. Read [SECURITY.md](../SECURITY.md) first.

The single most important rule: **the key-encryption-key (KEK) is never stored in the application
database, and KEK loss is total, unrecoverable data loss.** Everything below follows from that.

## Components an operator secures

| Component | What it holds | Where it must live |
|---|---|---|
| Application database (`amkeyward` schema) | Ciphertext envelopes, wrapped DEKs, audit chain, grants | SQL Server you control |
| **KEK store** | The key-encryption-key(s) that wrap every DEK | **Outside** the database (Key Vault / HSM / protected key file) |
| Break-glass trail | Append-only non-repudiation log | **Outside** the database, on storage the DB admin cannot rewrite |
| Database logins | Runtime (least-privilege) + migration (DDL) | Secret store / CI, never in source |

## Encryption model (what you are protecting)

Each secret value is sealed with a per-value **DEK** (AES-256-GCM); the DEK is **wrapped by the KEK** and
only the wrapped DEK is stored, alongside the `kekId` (KEK key-version). The AAD binds each ciphertext to
its exact logical slot (tenant / owner / project / environment / item / version), so a ciphertext cannot
be replayed into another slot. To decrypt anything you need **both** the database **and** a KEK store that
can resolve every referenced `kekId`.

## Backup & restore

Back up the database and the KEK store **separately** (different schedules and locations) — never together,
or a single leaked backup yields plaintext.

**Restore order (must hold):**

1. Restore / confirm the **KEK store** first. It must contain **every `kekId` the database references**
   (the current version and any still inside a rotation overlap window).
2. Restore the **database**.
3. Run the **KEK-integrity check** (below) before serving traffic — it confirms every stored envelope
   resolves under an available KEK. If it reports unresolvable envelopes, you restored a database newer
   than your KEK store (or destroyed a KEK version too early) — fix the KEK store before going live.

**KEK backup is special:** keep it offline and split (e.g. Shamir), and **rehearse the restore** — an
untested KEK backup is not a backup. Schedule a periodic backup-verify drill.

### KEK-integrity check (consistency job)

`IKekIntegrityVerifier` scans every stored envelope and reports any whose `kekId` the current provider
cannot resolve. It runs automatically on a schedule (the ops monitor, hourly) and surfaces through the
health endpoint; run it on demand after any restore. It runs under the system read bypass (a FILTER-only
`SESSION_CONTEXT` flag), so it scans every tenant under the normal least-privilege runtime login — no
elevated login is needed.

## KEK rotation

Rotation re-wraps every DEK under the new KEK version — one unwrap+wrap per row (a KEK round-trip each),
tracked per row by `kekId`. It is a resumable, observable job, not a cheap operation.

1. Introduce the new KEK version; keep the **old version enabled** (the overlap window) so both resolve.
2. Re-wrap rows from the old version to the new; the integrity check stays green throughout because both
   versions are available.
3. When **zero** rows reference the old version, **disable** it, then **destroy** it only after a safety
   window. Destroying a KEK version while rows still reference it makes those values undecryptable.

## KEK compromise response

A leaked KEK exposes any DEK an attacker can also reach. Re-wrapping does **not** undo prior exposure.

1. Rotate the KEK (above) so new wraps use a fresh version.
2. **Flag affected secrets for source rotation** — rotate the underlying credentials (API keys, passwords,
   connection strings) at their source, because the plaintext may already be known.
3. Review the audit chain and break-glass trail for unexpected access.

## DSGVO / GDPR — right to erasure (crypto-shredding)

The audit chain stores an **opaque pseudonym** for each actor, not their identity. The actor's PII lives
in the `AuditSubjects` table, encrypted under a **per-subject key**. Erasing a data subject
(`IAuditSubjectDirectory.EraseAsync`) destroys that PII so it is irrecoverable, while the pseudonym stays
in the immutable audit chain — the chain still verifies intact. Deleting an account removes the user's
personal vaults (items and encrypted versions cascade) **immediately, in the same operation** — there is
no retention/grace window; if your policy requires one, export first or delay the deletion itself.

## Monitoring & health

Two HTTP endpoints (anonymous, detail-free by default — the body is just the status word; put detail
behind your own auth if you expose them):

- `GET /health` — **liveness**: a live KEK wrap/unwrap probe. Unhealthy ⇒ the KEK store is unreachable and
  nothing can be decrypted.
- `GET /health/ready` — **readiness**: the above plus the cached ops-monitor snapshot.

The **ops monitor** (`OpsMonitorBackgroundService`, hourly) verifies KEK integrity, walks each tenant's
audit hash chain, and counts tokens nearing expiry, logging anomalies. Alert your log pipeline on:

- KEK integrity failures (restored without the KEK store / KEK retired too early),
- audit-chain verification failures (history altered out of band),
- auth-failure and break-glass spikes,
- imminent software-client token expiry.

A **chain-head checkpoint** should be exported out-of-band periodically so a DB admin who rewrites history
is detectable against the external checkpoint.

## Break-glass (emergency access)

Recovering server-side material is **dual-control**: one System Admin requests with a reason, a **different**
System Admin approves, and the grant is consumable once within its validity window
(`Keyward:BreakGlass:ValidityMinutes`, default 60). Every transition is written to the audit chain **and**
to the out-of-band append-only sink (`Keyward:BreakGlass:SinkFilePath`).

Point `SinkFilePath` at storage the **database admin cannot rewrite** (separate host / restricted
permissions) — that separation is what makes the trail non-repudiable. The file is hash-chained, so
deletion or edits break the chain and are detectable.

## Database swap / refresh under a running app

AM KEYWARD migrates on startup. If the database is swapped under a running instance (e.g. a nightly
production copy into test), the startup migration is bypassed. The cleanest fix is **operational** — recycle
the app whenever the DB is swapped. The in-app safety-net (`DatabaseMigration` section, `Enabled` +
`CheckIntervalSeconds`) periodically re-applies pending migrations as a backstop.

## Quick configuration reference

| Section | Keys | Purpose |
|---|---|---|
| `ConnectionStrings:Keyward` | — | SQL Server connection (runtime login) |
| `Keyward:BreakGlass` | `SinkFilePath`, `ValidityMinutes` | Out-of-band break-glass trail + grant window |
| `DatabaseMigration` | `Enabled`, `CheckIntervalSeconds` | Runtime migration safety-net |

The KEK itself is supplied by the host's KEK provider (a key file outside the DB in the reference shell;
Key Vault / HSM in production) — never via `appsettings`.
