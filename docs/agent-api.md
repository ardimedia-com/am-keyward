# Agent API and MCP server

An **agent token** lets an AI assistant (for example Claude Code) work with KEYWARD **as the person who issued it**,
narrowed to what that person ticked:

- **Vault entries** — only in the vaults put on its allowlist, only with the permissions ticked. The typical use:
  credentials arrive by e-mail; the assistant stores them in KEYWARD and hands the person a link, instead of
  leaving them in a local file.
- **Applications** (permission «Manage applications») — the assistant sets up an application for the
  [software-client API](software-client-api.md): the application, its environments and its secret keys, and hands
  the person a link to paste the values. It sets a value itself only when it legitimately holds it, and only
  write-only. App tokens stay with people.

Both can be limited to given networks.

## Security model

- **Acts as its user.** Every request runs as the token's user: their vault grants and roles apply, and every
  action is audited as the agent with its token id.
- **Checked on every request.** The token must be active, its user enabled and still a tenant member.
  - Vaults: the vault must be on the allowlist and opened to agents (a team-vault setting under «Share»), and the
    user must hold the needed grant. Personal vaults are never reachable.
  - Applications: the token must hold «Manage applications», its user must still be allowed to manage the software
    side (system admin, tenant admin or software manager), and the application must be on the token's allowlist or
    created by this very token.
  - Closing the vault, removing the grant or role, taking an application off the list, disabling the user or
    revoking the token takes effect on the next call.
- **Write-only.** Creating and changing never echoes a value back. A Login's URL and user name are the only vault
  fields an agent can read. For applications no endpoint returns a value — not even a masked prefix; the agent
  sees only «value set yes/no» and the version.
- **The entry link first.** Wherever an agent needs a value it hands the person the entry's deep link (every item
  and every reveal request carries it): the person opens the entry and copies the value there.
- **Revealing a vault secret needs a human, every time.** An agent asks to see one field with a reason; the
  token's user approves or rejects it on the «AI agent tokens» page within 5 minutes; an approved value can be fetched
  **once**, within 60 seconds. The MCP server puts it on the Windows clipboard (excluded from clipboard history and
  cloud sync, cleared after 30 seconds) — never into the assistant's context. The reason is the agent's own text:
  decide on what you know, not on what it says. Application values cannot be revealed at all.
- **App tokens are human-only.** An agent can neither issue, reveal, rotate nor revoke a software-client token. It
  may read their metadata — name, environment, status, expiry, last access, heartbeat monitoring, access statistics —
  never a token or its prefix. The application response carries the link to the page where a person issues one.
- **Move, never delete.** An agent with «Create and update entries» may move an entry into another folder or another
  reachable vault (Write needed on both); no agent endpoint deletes a vault entry.
- **Renaming and deleting is narrow.** An agent may rename or delete only a key **it created itself** that holds no
  value (no value row at all) in any environment, and only an application **it created itself** that holds no value,
  no key of someone else and no issued app token. Everything else is refused with 403 and left to a person in the UI:
  a key a program already reads, or anything a person put there, is not an agent's to change.
- **One rule set.** Every application change goes through the same services as the UI, so names, keys and
  environments are validated identically — the error messages are the same.
- **Throttled.** Per-token rate limit; failed authentications are throttled per client IP; optional network
  restriction per host and per token.
- **Out of reach answers 404**, exactly like something missing — the API does not reveal what exists. Only the
  application collection answers 403 when the token lacks «Manage applications», which tells nothing about data.

## Issuing a token

On **Agent tokens** (navigation, under the vaults): name, vaults (only those opened to agents) with their
permissions, validity (default 90 days, at most 365) and optional networks in CIDR notation. The value is shown
once. A person with Manage opens a team vault to agents in its «Share» section.

A user who may manage the software side also sees **Applications**: tick «Manage applications» (unticked by
default), then the existing applications the token may manage and/or «May create new applications». Vault
permissions only count when a vault is ticked, so a token can be for applications only.

Instead of listing them, a token can reach **all team vaults opened to agents** and/or **all applications** — today's
and future ones. For vaults this only replaces the list: each vault must still be opened to agents, and the user
must still hold the grant. **Edit** changes a token's name, permissions, vaults, applications and networks at any
time; its value and validity stay, so nothing has to be set up again on the computer (audited as an update).
**Revoke** stops a token at once; a revoked or expired token can then be **deleted** from the list (audited; a working
token cannot be deleted, only revoked). Tenant and system administrators see every token of the organisation with its
owner in their own section and can revoke one — a lost computer, someone who left — but not edit or issue one for
someone else.

| Permission | Allows |
|---|---|
| List entries | `/vaults`, `/vaults/{id}/tree`, `/search` |
| Read URL and user name | `GET /items/{id}` |
| Create and update entries | `POST /vaults/{id}/items`, `PATCH /items/{id}`, `POST /items/{id}/move` |
| Ask to see a secret | `POST /items/{id}/reveal-requests`, then consume after approval |
| Manage applications | `/applications…` below — never a value; app tokens read-only (metadata) |

## Endpoints

Base path `/keyward/api/v1/agent`, `Authorization: Bearer amkwa_…`. Errors are RFC 9457 problem details.

| Method | Path | Notes |
|---|---|---|
| GET | `/ping` | 204 when the token works |
| GET | `/token` | the token's own name, permissions, vault and application counts, «may create», networks, expiry |
| GET | `/vaults` | reachable vaults |
| GET | `/vaults/{id}/tree` | folders, item names and types |
| GET | `/search?q=` | by name, ≥ 2 characters, ≤ 100 hits |
| GET | `/items/{id}` | name, type, folder, link, version (also the ETag); Login: URL and user name |
| POST | `/vaults/{id}/items` | Login: `url`, `username`, `password`, `note`; other types: `value`. 201, no echo |
| PATCH | `/items/{id}` | `If-Match: "<version>"` required (428 without, 412 when changed meanwhile); Login field by field, other types by `value` |
| POST | `/items/{id}/move` | `{ "vaultId", "folderId"? }` — another folder and/or another reachable vault (Write on both). 200 with link (unchanged) and version; across vaults the id changes |
| POST | `/items/{id}/reveal-requests` | `{ "field": "Password" \| "Note" \| "Value", "reason": "…" }` → 202, pending |
| GET | `/reveal-requests/{id}` | status only: Pending, Approved, Rejected, Expired, Consumed |
| POST | `/reveal-requests/{id}/consume` | the value, once (`Cache-Control: no-store`); otherwise 409 |
| GET | `/applications` | reachable applications: name, environments, keys, per environment `valueSet` + `versionId`, `link`, `tokensLink`. 403 without the permission |
| POST | `/applications` | `{ "name", "environments": [] }` → 201. Starts with the tenant's default environments; listed ones are added. Needs «May create new applications» (403 otherwise) |
| GET | `/applications/{id}` | one application, as in the list; per environment also `rotateBy` and `rotationNote` |
| GET | `/applications/{id}/tokens` | app tokens: name, environment, status (Pending/Active/Expired/Revoked), note, expiry, last access, monitoring — never a token |
| GET | `/applications/{id}/statistics?days=30` | requests per token and day, client addresses, access alerts (1–90 days) |
| PATCH | `/applications/{id}` | `{ "name" }` — only an application this token created and that is still empty |
| DELETE | `/applications/{id}` | 204 — same condition |
| POST | `/applications/{id}/environments` | `{ "name" }` → 201 |
| POST | `/applications/{id}/secrets` | `{ "key", "environment"?, "value"? }` → 201. Without `value` a placeholder «not set»; with one, `environment` is required. No echo; ETag = version |
| PUT | `/applications/{id}/secrets/{key}` | `{ "environment", "value" }` with `If-Match: "<versionId>"`, or `If-None-Match: *` while the environment holds no value. 428 without, 412 when changed meanwhile. 200 with version and link, no echo |
| PATCH | `/applications/{id}/secrets/{key}` | `{ "key" }` rename — only a key this token created that holds no value |
| DELETE | `/applications/{id}/secrets/{key}` | 204 — same condition |

`link` opens the application on its keys and values (`/amkeyward/applications?app={id}&tab=data`), `tokensLink` on
its app tokens (`&tab=tokens`). Both are paths on the KEYWARD host; the MCP server makes them absolute. Status codes:
400 invalid name/key/environment (same message as the UI), 403 permission or rename/delete refused, 404 out of reach
or missing, 409 name/key/environment already exists, 412/428 as above.

## Enabling on a host

The API is part of `Am.Keyward.Api`. A host adds it next to the software-client API:

1. **Register** — `builder.Services.AddKeywardAgentApi(o => o.AllowedNetworks = builder.Configuration["Keyward:Agent:AllowedNetworks"]);`
   Options: `PermitLimit` (default 120 per minute per token), `FailedAuthenticationLimit`/`Window`, `AllowedNetworks`.
2. **Middleware** — `app.UseRateLimiter()` must run before the mapped endpoints (the limiter partitions by the
   bearer header, so its place relative to `UseAuthentication()` does not matter).
3. **Map** — `app.MapKeywardAgentApi();` — only when `AllowedNetworks` is set, so the API is never exposed by
   accident.
4. **Networks** — `AllowedNetworks` is a comma-separated CIDR list (LAN, internal Wi-Fi, VPN pools). Callers from
   elsewhere get 403 before any token is looked up. The check uses the address the host sees: **behind a reverse
   proxy every internet request arrives with the proxy address**, so keep that address outside the list, and resolve
   the real client address with `ForwardedHeaders` trusted from that known proxy only. The per-token networks follow
   the same rule.
5. **Alert presenter** — implement `IKeywardAlertPresenter.NotifyRevealRequestAsync` so users hear about a reveal
   request within its 5 minutes (a default that does nothing exists; without an implementation users must keep the
   «AI agent tokens» page open).
6. **Schema** — the host's usual `KeywardSchemaMigrator` run applies the migrations (`AgentTokens`, `RevealRequests`,
   `AgentApplicationManagement`, …).

Reference: `bvd.li.toolbox` (`Program.cs`: `AddKeywardAgentApi`, `ForwardedHeaders` with `KnownProxies`,
`MapKeywardAgentApi` only with `Keyward:Agent:AllowedNetworks`; `appsettings.json`: `Keyward:Agent` and
`ForwardedHeaders:KnownProxies`).

### Checklist: ardimedia.com.toolbox (toolbox.ardimedia.com)

Today it maps only the software-client API (`AddKeywardSoftwareClientApi` / `MapKeywardClientApi`), and
`app.UseRateLimiter()` is already in place. It runs on svrwww05 (IIS) like the BVD toolbox; the public name goes
through the reverse proxy. The lines it needs, all in `Ardimedia.Com.Toolbox.Ui.App.Blazor`:

- [ ] `Program.cs`, next to `builder.Services.AddKeywardSoftwareClientApi();` (inside the Keyward-enabled block):

  ```csharp
  builder.Services.AddKeywardAgentApi(o => o.AllowedNetworks = builder.Configuration["Keyward:Agent:AllowedNetworks"]);
  ```

- [ ] `Program.cs`, before `builder.Build()` — only if the reverse proxy is not yet trusted for `X-Forwarded-For`:

  ```csharp
  builder.Services.Configure<ForwardedHeadersOptions>(options =>
  {
      options.ForwardedHeaders = ForwardedHeaders.XForwardedFor;
      options.ForwardLimit = 1;
      options.KnownProxies.Clear();
      options.KnownIPNetworks.Clear();
      foreach (string proxy in builder.Configuration.GetSection("ForwardedHeaders:KnownProxies").Get<string[]>() ?? [])
      {
          options.KnownProxies.Add(IPAddress.Parse(proxy));
      }
  });
  ```

  and `app.UseForwardedHeaders();` as the first middleware after `builder.Build()`.
- [ ] `Program.cs`, next to `app.MapKeywardClientApi();`:

  ```csharp
  if (string.IsNullOrWhiteSpace(app.Configuration["Keyward:Agent:AllowedNetworks"]))
  {
      app.Logger.LogWarning("KEYWARD agent API not mapped: Keyward:Agent:AllowedNetworks is not set.");
  }
  else
  {
      app.MapKeywardAgentApi();
  }
  ```

- [ ] `appsettings.json` — `ForwardedHeaders:KnownProxies` with the reverse proxy address(es), and under `Keyward`:

  ```json
  "Agent": {
    "AllowedNetworks": "<LAN>, <internal Wi-Fi>, <VPN pools>"
  }
  ```

  Never the proxy's network (DMZ).
- [ ] `KeywardAlertPresenter` — add `NotifyRevealRequestAsync` (the BVD toolbox's presenter is the template).
- [ ] Deploy, then check `https://toolbox.ardimedia.com/keyward/api/v1/agent/ping` from outside the allowed networks
  (403) and inside (401 without a token, 204 with one), and run `amkeyward-mcp check`.

## MCP server (`Am.Keyward.Mcp`)

A .NET tool (`amkeyward-mcp`) that speaks MCP over stdio.

- Vault tools: `list_vaults`, `list_items`, `search`, `get_item`, `create_login`, `create_item`, `update_item`,
  `move_item`, `request_reveal`, `consume_reveal`. `get_item` and `request_reveal` hand out the entry link — usually
  the simplest way: the person copies the value in KEYWARD.
- Application tools: `list_applications`, `create_application`, `add_environment`, `create_secret_key` (a placeholder
  for a person to fill) and `set_secret_value` (write-only; its description tells the assistant never to take a value
  from the chat unless the user gave it for exactly this purpose), plus the read-only `list_app_tokens` and
  `get_app_statistics`. Every answer carries the UI link.

```powershell
dotnet tool install --global Am.Keyward.Mcp --prerelease
amkeyward-mcp setup https://keyward.example.com   # paste the agent token; stored in the Windows Credential Manager
$env:Keyward__ServiceUri = "https://keyward.example.com"
amkeyward-mcp check                               # verifies the token and prints its permissions
```

Register it in Claude Code (the token is not part of the configuration):

```powershell
claude mcp add amkeyward-keyward-example-com --scope user --env Keyward__ServiceUri=https://keyward.example.com -- amkeyward-mcp
```

The «AI agent tokens» page shows these commands filled in with its own address.

**Several KEYWARD installations on one computer** (e.g. two companies' toolboxes): nothing about them is built into
the tool. Each token is stored under its KEYWARD's address (`AmKeyward:Agent:<host>`), and each installation is its
own MCP registration with its own `Keyward__ServiceUri` — run `setup` and `claude mcp add` once per installation. A
token stored by a version before 0.24 (target `AmKeyward:Agent`) is still found as a fallback.

**Where a token applies:** every Claude Code session of that Windows user on that computer (`--scope user`), all
acting as the token's user. Use one token per computer, named after it; Claude Desktop and claude.ai have their own
MCP configuration.

**Removing it again** (the page shows these filled in, under «How to remove it again»); each step stands on its own:

```powershell
claude mcp remove amkeyward-keyward-example-com --scope user   # the registration in Claude Code
amkeyward-mcp remove https://keyward.example.com               # the stored token (also the pre-0.24 one)
dotnet tool uninstall --global Am.Keyward.Mcp                   # only if no other KEYWARD uses it
```

Then revoke the token on «AI agent tokens» and delete it from the list. For a lost computer revoking alone is enough:
a revoked token is useless wherever it is still stored.

Without the Credential Manager (not Windows) the token comes from `KEYWARD_AGENT_TOKEN`; revealing is then refused,
because there is no clipboard to send the value to.

### Example: an application for a console

`Am.PionexCom.Cmd.BotWatch` needs `PionexOwnerBotWatch:ApiKey` and `PionexOwnerBotWatch:ApiSecret` in `Production`.
The assistant calls `create_application("Am.PionexCom.Cmd.BotWatch", ["Production"])`, then `create_secret_key` for
both keys, and hands the person the link. The person pastes the values on the application's «Data» tab and issues
the app token on its «Client tokens» tab; the console reads its secrets through the software-client API.
