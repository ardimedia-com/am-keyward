# Software-client API

A deployed application reads its secrets by presenting a **software-client token** ("app token" in the UI)
as a Bearer token.
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

## Token lifecycle

- **Pending placeholders.** Creating an application (or adding an environment) automatically creates one
  token per environment as a **pending placeholder without a secret** — visible and named, but unable to
  authenticate until its first value is generated on the app-tokens page ("Generate token value"). A
  placeholder is not a credential.
- **Names.** Left empty at issuance, the server names the token `<application>-<environment>` (numbered
  `-2`, `-3`, … when taken). Names are **unique per application** (enforced in the service and by a unique
  index), so a token stays identifiable in lists and audits; multiple tokens per environment are
  deliberately allowed — they just need distinct names.
- **Issue / rotate / revoke / reactivate / delete.** The plaintext is returned **once** (at issue, mint or
  rotate) and never stored — only a SHA-256 hash. Revoking disables a token (reversible: reactivating makes
  the same stored secret valid again, expiry unchanged); deleting removes the record permanently. Deleting
  an environment (or a whole application) **deletes** its tokens. Every lifecycle change is written to the
  tamper-evident audit chain.

## Issuing a token

Tokens are issued by an administrator through the app-tokens UI or the management API. Store the plaintext
where the client can read it (an environment variable, a deployment secret) and treat it like a password.

```
POST /keyward/api/v1/tenants/{tenantId}/projects/{projectId}/environments/{environment}/tokens
{ "name": "orders-service prod", "expiresAt": "2027-01-01T00:00:00Z" }
```

`expiresAt` is optional but recommended. Manage tokens with:

- `GET    .../projects/{projectId}/tokens` — list (never returns the secret)
- `POST   .../projects/{projectId}/tokens/{tokenId}/rotate` — issue a new secret on the same token
- `DELETE .../projects/{projectId}/tokens/{tokenId}` — revoke

## Rotation without downtime

Rotating a token replaces its secret immediately, so the old secret stops working at once — and it
**restarts the validity window**: `Created` becomes the rotation time and, unless you pass a new expiry,
the original lifetime is re-applied from now (an expired token becomes a fresh one; a token never silently
turns into one that never expires). For a zero-downtime rollover, **issue a second token**, deploy it to
the fleet, then **revoke the old one** once every instance has picked up the new value.

**Expiry notifications:** administrators who opt in on their profile page receive an e-mail 30, 20 and 10
days before a token expires, then daily from 9 days; a background watcher additionally logs due tokens.

## Security notes

- Tokens carry no secret material at rest — only a SHA-256 hash and a non-secret lookup prefix are stored.
- The token determines the tenant scope server-side; reads are additionally constrained by the database
  row-level-security policy (see [database logins](database-logins.md)).
- The management API above requires a signed-in admin (the host's authorization policy), and the route's
  `{tenantId}` is verified against the signed-in user's tenant membership — non-members get 403 (system
  admins count as members of every tenant).
