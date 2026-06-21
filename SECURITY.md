# Security Policy

AM KEYWARD is a credential & secrets manager in **early development (pre-1.0)**. Its design has **not**
yet undergone an external security review. Do not use it to store real secrets yet.

## Reporting a vulnerability

Please report security issues **privately** — do **not** open a public GitHub issue.

- Email: **harry@ardimedia.com**

Include affected version/commit, a description, and reproduction steps. We will acknowledge and work
with you on a coordinated disclosure.

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
- Backups of the database and the KEK store (on separate schedules/locations).

## No warranty

Provided "as is" under the [MIT license](LICENSE), without warranty of any kind.
