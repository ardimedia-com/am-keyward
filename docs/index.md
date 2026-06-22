# AM KEYWARD — Documentation

This folder holds the **end-user and operator documentation**. It is kept in sync with the
installed / user-visible features as they ship (the project is in early development, so it grows with
the implementation).

## Available now

- [Operations & KEK/DR runbook](operations-runbook.md) — key custody, backup/restore order, KEK rotation
  and compromise response, monitoring/health endpoints, break-glass, GDPR erasure.
- [Software-client API](software-client-api.md) — how a deployed app fetches its secrets with a token.
- [Database logins](database-logins.md) — the least-privilege runtime login vs. the migration login.

## Planned sections

- **Getting started (operator)** — deploy the standalone app or embed the libraries; configure the
  database (Microsoft SQL Server) and the KEK provider.
- **User guide** — software credentials (projects, environments, API tokens) and personal & shared
  vaults.
- **Administration** — tenants, groups, roles, audit, recovery.
