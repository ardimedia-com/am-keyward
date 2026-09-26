# Agent API and MCP server

An **agent token** lets an AI assistant (for example Claude Code) work with vault entries **as the person who
issued it** — only in the vaults put on its allowlist, only with the permissions ticked, and, if configured, only
from given networks. The typical use: credentials arrive by e-mail; the assistant stores them in KEYWARD and hands
the person a link, instead of leaving them in a local file.

## Security model

- **Acts as its user.** Every request runs as the token's user: their vault grants apply, and every action is
  audited as the agent with its token.
- **Checked on every request.** The token must be active, its user enabled and still a tenant member, the vault on
  the allowlist and opened to agents (a team-vault setting under «Share»), and the user must hold the needed
  grant. Closing the vault, removing the grant, disabling the user or revoking the token takes effect on the next
  call. Personal vaults are never reachable.
- **Write-only by default.** Creating and changing entries never echoes a value back. A Login's URL and user name
  are the only fields an agent can read.
- **Revealing needs a human, every time.** An agent asks to see one field with a reason; the token's user approves
  or rejects it on the «Agent tokens» page within 5 minutes; an approved value can be fetched **once**, within 60
  seconds. The MCP server puts it on the Windows clipboard (excluded from clipboard history and cloud sync, cleared
  after 30 seconds) — never into the assistant's context. The reason is the agent's own text: decide on what you
  know, not on what it says.
- **Throttled.** Per token rate limit; failed authentications are throttled per client IP.
- Out of reach answers **404**, exactly like a missing entry — the API does not reveal what exists.

## Issuing a token

On **Agent tokens** (navigation, under the vaults): name, vaults (only those opened to agents), permissions, validity
(default 90 days, at most 365) and optional networks in CIDR notation. The value is shown once. A person with
Manage opens a team vault to agents in its «Share» section.

| Permission | Allows |
|---|---|
| List entries | `/vaults`, `/vaults/{id}/tree`, `/search` |
| Read URL and user name | `GET /items/{id}` |
| Create and update entries | `POST /vaults/{id}/items`, `PATCH /items/{id}` |
| Ask to see a secret | `POST /items/{id}/reveal-requests`, then consume after approval |

## Endpoints

Base path `/keyward/api/v1/agent`, `Authorization: Bearer amkwa_…`. Errors are RFC 9457 problem details.

| Method | Path | Notes |
|---|---|---|
| GET | `/ping` | 204 when the token works |
| GET | `/vaults` | reachable vaults |
| GET | `/vaults/{id}/tree` | folders, item names and types |
| GET | `/search?q=` | by name, ≥ 2 characters, ≤ 100 hits |
| GET | `/items/{id}` | name, type, folder, link, version (also the ETag); Login: URL and user name |
| POST | `/vaults/{id}/items` | Login: `url`, `username`, `password`, `note`; other types: `value`. 201, no echo |
| PATCH | `/items/{id}` | `If-Match: "<version>"` required (428 without, 412 when changed meanwhile); Login field by field, other types by `value` |
| POST | `/items/{id}/reveal-requests` | `{ "field": "Password" \| "Note" \| "Value", "reason": "…" }` → 202, pending |
| GET | `/reveal-requests/{id}` | status only: Pending, Approved, Rejected, Expired, Consumed |
| POST | `/reveal-requests/{id}/consume` | the value, once (`Cache-Control: no-store`); otherwise 409 |

A host maps the API with `builder.Services.AddKeywardAgentApi()` and `app.MapKeywardAgentApi()`
(`app.UseRateLimiter()` before `app.UseAuthentication()`), and implements
`IKeywardAlertPresenter.NotifyRevealRequestAsync` so users hear about reveal requests in time. Expose the path to
your LAN/VPN only (IIS or firewall), in addition to the per-token networks.

## MCP server (`Am.Keyward.Mcp`)

A .NET tool (`amkeyward-mcp`) that speaks MCP over stdio. Tools: `list_vaults`, `list_items`, `search`, `get_item`,
`create_login`, `create_item`, `update_item`, `request_reveal`, `consume_reveal`.

```powershell
dotnet tool install --global Am.Keyward.Mcp --prerelease
amkeyward-mcp setup            # paste the agent token; stored in the Windows Credential Manager ("AmKeyward:Agent")
$env:Keyward__ServiceUri = "https://toolbox.bvd.li"
amkeyward-mcp check            # verifies the token
```

Register it in Claude Code (the token is not part of the configuration):

```powershell
claude mcp add amkeyward --scope user --env Keyward__ServiceUri=https://toolbox.bvd.li -- amkeyward-mcp
```

Without the Credential Manager (not Windows) the token comes from `KEYWARD_AGENT_TOKEN`; revealing is then refused,
because there is no clipboard to send the value to.
