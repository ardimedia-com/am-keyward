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
| Database logins | Migration (DDL), plus an optional least-privilege runtime login | Per installation (a site-local secrets file), never in source — and not a machine-wide variable with a generic name, which every app on the box inherits |

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

**Key file access (Windows, `DpapiKekFile`).** Local-machine DPAPI lets any process on the server unprotect
`kek.bin` once it can read it. The app therefore narrows the KEK folder and the file to SYSTEM, Administrators and
its own identity (inheritance off) every time it loads the key; explicit grants to individual accounts (e.g. a
second installation that shares the KEK under its own app-pool identity) are kept, grants to groups (Users,
IIS_IUSRS, …) are removed. If it may not change the rules — a folder an administrator created, e.g. by
`--keyward-import-kek` — it logs a warning: narrow the folder by hand once. Two installations sharing one KEK
should run under the same identity, or the second one needs an explicit grant on the folder.

**Escrow passphrase.** `--keyward-export-kek` requires a passphrase of at least 20 characters
(`DpapiKekEscrow.MinimumPassphraseLength`) — it alone protects the escrow blob. Older blobs still import.

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

1. Introduce the new KEK version in a `KeyRingKekProvider`; keep the **old version enabled** (the overlap window) so
   both resolve. The ring also opens values stored under a legacy, unqualified id of the old key.
2. Run `KekRewrapService.RewrapAsync()` (resolve it from the host's services, e.g. behind an admin action or a
   one-off startup switch). It re-wraps only the data keys — no value is decrypted — in secret versions, vault-entry
   versions, audit-subject PII and the key-ownership canary, in batches, each written with a `KekRewrap` audit
   entry. It is idempotent: run it again until its result reports no rows left under the old id. The integrity
   check stays green throughout because both versions are available. The job refuses to run while the key is
   blocked (key-ownership Conflict).
3. When **zero** rows reference the old version, **disable** it, then **destroy** it only after a safety
   window. Destroying a KEK version while rows still reference it makes those values undecryptable.

## KEK compromise response

A leaked KEK exposes any DEK an attacker can also reach. Re-wrapping does **not** undo prior exposure.

1. Rotate the KEK (above) and re-wrap, so every data key moves to a fresh version.
2. **Flag affected secrets for source rotation** — rotate the underlying credentials (API keys, passwords,
   connection strings) at their source, because the plaintext may already be known.
3. Review the audit chain and break-glass trail for unexpected access.

## DSGVO / GDPR — right to erasure (crypto-shredding)

The audit chain stores an **opaque pseudonym** for each actor, not their identity. The actor's PII lives
in the `AuditSubjects` table, encrypted under a **per-subject key**. Erasing a data subject
(`IAuditSubjectDirectory.EraseAsync`) destroys that PII so it is irrecoverable, while the pseudonym stays
in the immutable audit chain — the chain still verifies intact.

**Account deletion and retention.** Call `IKeywardAccountDeletion.DeleteAccountAsync` from your delete-user action
(the reference shell does). The user is disabled at once; their personal vaults are kept for
`Keyward:Retention:PersonalVaultRetentionDays` (default 90) and then removed by the daily retention job. Enabling
the user again cancels the deletion. Team vaults are never touched. Reveal requests are purged after
`RevealRequestRetentionDays` (default 30).

## Monitoring & health

Two HTTP endpoints (anonymous, detail-free by default — the body is just the status word; put detail
behind your own auth if you expose them):

- `GET /health` — **liveness**: a live KEK wrap/unwrap probe. Unhealthy ⇒ the KEK store is unreachable and
  nothing can be decrypted.
- `GET /health/ready` — **readiness**: the above plus the cached ops-monitor snapshot.

The **ops monitor** (`OpsMonitorBackgroundService`, hourly) re-checks key ownership (the canary), verifies KEK
integrity, walks each tenant's audit hash chain (the new tail every hour, the whole chain daily), verifies the
break-glass trail and the audit anchors, and counts tokens nearing expiry, logging anomalies. `/health/ready`
reports Unhealthy on a key-ownership Conflict, a broken trail or a second instance, and Degraded when a trail has
damaged lines. Alert your log pipeline on:

- KEK integrity failures (restored without the KEK store / KEK retired too early),
- audit-chain verification failures (history altered out of band),
- auth-failure and break-glass spikes,
- imminent software-client token expiry.

**Audit anchors.** With an out-of-band path configured, the ops monitor appends each verified chain head to
`audit-anchors.jsonl` next to the break-glass trail (`AuditAnchorsEnabled`, `AuditAnchorFilePath`). Verification
fails when the database is behind or differs from the latest anchor — removed entries or an older database copy.
Use one anchor file per database; after a **deliberate** restore of an older database, archive the anchor file so
the old head does not count against the restored chain.

## Break-glass (emergency access)

Recovering server-side material is **dual-control**: one System Admin requests with a reason, a **different**
System Admin approves, and the grant is consumable once within its validity window
(`Keyward:BreakGlass:ValidityMinutes`, default 60). Every transition is written to the audit chain **and**
to the out-of-band append-only sink (`Keyward:BreakGlass:SinkFilePath`).

`SinkFilePath` is **required outside Development** — the host refuses to start without it. Point it at storage
the **database admin cannot rewrite** (separate host / restricted permissions) — that separation is what makes
the trail non-repudiable. The file is hash-chained and written under an exclusive lock, so two writers cannot fork
it; deletion or edits break the chain and are detectable. A torn last line (a crash mid-append) is skipped and
reported as Degraded — inspect the file, never delete lines.

## Database swap / refresh under a running app

AM KEYWARD migrates on startup. If the database is swapped under a running instance (e.g. a nightly
production copy into test), the startup migration is bypassed. The cleanest fix is **operational** — recycle
the app whenever the DB is swapped. The in-app safety-net (`DatabaseMigration` section, `Enabled` +
`CheckIntervalSeconds`) periodically re-applies pending migrations as a backstop and then re-checks key ownership,
so an instance never keeps writing under a key the swapped-in database does not belong to.

## Quick configuration reference

| Section | Keys | Purpose |
|---|---|---|
| `ConnectionStrings:Keyward` | — | SQL Server connection (runtime login) |
| `Keyward:BreakGlass` | `SinkFilePath` (required outside Development), `ValidityMinutes`, `AuditAnchorsEnabled`, `AuditAnchorFilePath` | Out-of-band break-glass trail, grant window, audit-chain anchors |
| `Keyward:Retention` | `PersonalVaultRetentionDays` (90), `RevealRequestRetentionDays` (30) | Account-deletion grace period, reveal-request purge |
| `Keyward:TokenAccess` | `Enabled`, `FlushIntervalSeconds`, `RetentionDays`, `SilenceAlertDays` | Token access statistics + access-pattern alerts |
| `Keyward:Monitoring` | `Enabled`, `CheckIntervalSeconds`, `TimeZone` | Heartbeat monitoring (dead-man's switch); `TimeZone` (Windows or IANA id, the server's local zone when unset) is the installation's zone: watch windows, statistics day buckets and notification-mail timestamps |
| `DatabaseMigration` | `Enabled`, `CheckIntervalSeconds` | Runtime migration safety-net |

**One instance per database.** The background jobs (notification mails, statistics flush, heartbeat monitoring,
retention) are not coordinated across processes. Run exactly one instance per database — no web farm, no IIS web
garden, no overlapping deployment. A second instance logs an error and `KeywardSingleInstanceHealthCheck` reports
Unhealthy. Heartbeat monitoring can only alarm while the host itself runs: watch the host's `/health` endpoint with
an external check to cover the watcher. The allowed silence of a monitor is at least the check plus the flush
interval plus one minute (3 minutes by default).

The KEK itself is supplied by the host's KEK provider — never via `appsettings`. The reference shell uses a
plaintext key file in Development only; elsewhere a DPAPI-protected key file in `Keyward:Kek:Directory` (default
`%ProgramData%\Ardimedia\Am.Keyward\kek`, created exclusively and with protected access rules — back it up with the
escrow export). Embedding hosts may supply a KMS-backed `IKekProvider`.
