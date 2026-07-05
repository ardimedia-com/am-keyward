# Software-client API

A deployed application reads its secrets by presenting a **software-client token** as a Bearer token.
Each token is scoped to exactly one **(project, environment)**, so a token leaked from a Development host
cannot read Production. The server derives the tenant, project and environment from the token record — the
client never sends them.

## Endpoints

Base path: `/keyward/api/v1`. Authentication: `Authorization: Bearer <token>`. Requests are rate limited
per token.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/secrets` | All current key/value pairs for the token's environment (bulk load) |
| `GET` | `/secrets/{key}` | One secret by key (e.g. `ConnectionStrings:Main`) |

`GET /secrets` returns a flat JSON object (`{ "Section:Key": "value", ... }`) shaped for binding into
.NET `IConfiguration`.

## Issuing a token

Tokens are issued by an administrator through the management API (or, later, the admin UI). The plaintext
token is returned **once** at issuance and never stored — only a hash is kept. Store it where the client
can read it (an environment variable, a deployment secret) and treat it like a password.

```
POST /keyward/api/v1/tenants/{tenantId}/projects/{projectId}/environments/{environment}/tokens
{ "name": "orders-service prod", "expiresAt": "2027-01-01T00:00:00Z" }
```

`expiresAt` is optional but recommended. Manage tokens with:

- `GET    .../projects/{projectId}/tokens` — list (never returns the secret)
- `POST   .../projects/{projectId}/tokens/{tokenId}/rotate` — issue a new secret on the same token
- `DELETE .../projects/{projectId}/tokens/{tokenId}` — revoke

## Rotation without downtime

Rotating a token replaces its secret immediately, so the old secret stops working at once. For a
zero-downtime rollover, **issue a second token**, deploy it to the fleet, then **revoke the old one** once
every instance has picked up the new value. A background watcher logs tokens that are nearing expiry so you
can rotate them in time.

## Security notes

- Tokens carry no secret material at rest — only a SHA-256 hash and a non-secret lookup prefix are stored.
- The token determines the tenant scope server-side; reads are additionally constrained by the database
  row-level-security policy (see [database logins](database-logins.md)).
- The management API above requires a signed-in admin (the ASP.NET Core Identity application cookie). Note
  that it does **not yet verify tenant membership** — it trusts the route's `{tenantId}`, so a real
  multi-tenant deployment must add a membership check first. Do not expose this pre-1.0 build outside
  localhost.
