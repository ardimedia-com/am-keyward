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
