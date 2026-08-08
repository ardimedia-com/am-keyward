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

## .NET client — `Am.Keyward.Client`

.NET applications should not hand-roll these HTTP calls: the `Am.Keyward.Client` package wraps them as a
standard configuration provider (plus a typed client for on-demand reads):

```csharp
builder.Configuration.AddKeywardSecrets(o =>
{
    o.ServiceUri = new Uri("https://keyward.example.com");
    o.ApplicationName = "Bvd.Li.Toolbox";   // token read from KEYWARD_BVD_LI_TOOLBOX_TOKEN (see below)
    // o.ReloadInterval = TimeSpan.FromMinutes(15);   // optional periodic re-read
});
```

The token is resolved from the same per-application environment variable this document describes (or a
fixed `TokenEnvironmentVariableName`, or an explicit `Token`). By default a missing token or unreachable
server fails the host at startup — loudly, with the variable name in the message — after a short retry
window; `Optional = true` tolerates it with an empty source. See the README section *Consuming secrets
from a deployed application* for the full option list.

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

The UI shows the one-time plaintext together with a **ready-to-run PowerShell block** for the target
machine: it puts the token into a machine-scope environment variable and appends an `Invoke-RestMethod`
call against `GET /secrets` that proves the token works. Services pick the variable up after a restart.

The variable is named **per application** — `Bvd.Li.Toolbox` → `KEYWARD_BVD_LI_TOOLBOX_TOKEN` — so several
applications can be deployed to one host without colliding. A host whose applications all read one fixed
variable sets `KeywardUiOptions.TokenEnvironmentVariableName` instead.

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

## Access statistics & alerts

Every authenticated read is counted in memory and persisted batched (default every 60 s, section
`Keyward:TokenAccess`), so the server can answer "is this token still in use?" without a database write on
the hot path. Per token it records the **last access (time + client IP)**, **requests per day** (calendar
days in the installation's `Keyward:Monitoring:TimeZone`, server-local when unset), and
the **set of IPs it has been seen from** — shown in the app-tokens list and the application's «Statistics»
tab, and trimmed after the retention window (default 90 days). Two rule-based alerts derive from it: a
token used from a **never-seen IP**, and a token **active again after 30+ days of silence**; both appear
in the Statistics tab, and administrators can opt in on their profile to receive them by e-mail. Practical
uses: verify a fleet has switched tokens before revoking the old one (its last access stops moving), spot
a leaked token being used from an unexpected address, and find never-used placeholder tokens to clean up.
Note: the recorded IP is the connection's remote address — behind a proxy/load balancer configure
forwarded-headers middleware in the host, or the proxy's address is what gets recorded.

Independently of the per-token statistics, every successful software read is also recorded **per secret
and environment** (last read at, source client-token vs in-process, total count) and shown as the "Last
read" column in the application's Data tab — the direct answer to "is this secret still used?".
Management views don't count as reads, and these rows are never retention-trimmed.

## Heartbeat monitoring (dead-man's switch)

The access statistics answer "is this token still in use?" after the fact; **heartbeat monitoring** turns
the same signal into an active alarm for the failure an application cannot report itself: a scheduled task
that never started sends no error mail — it just goes silent. A consumer that loads its configuration
through Keyward leaves a heartbeat with every run (each process start reads its secrets), so per app token
you can enable a monitor on the application's «Monitoring» tab:

- **Maximum silence** — how long the token may stay without an access before the monitor goes **down**
  (e.g. 26 h for a daily job with buffer). One value; build your grace into it.
- **Watch window** — weekdays and optional daily hours during which silence counts. Outside the window the
  clock pauses, so a Monday-to-Friday job does not false-alarm over its scheduled weekend. Window times
  are wall clock in the app-wide `Keyward:Monitoring:TimeZone` (Windows or IANA id; the server's local
  zone when unset) — that same zone also buckets the statistics days and stamps the notification mails.
  Timestamps are always STORED in UTC; the UI renders them in the viewer's own local time zone.
- **All-clear** — optionally a recovery mail when the heartbeat returns.
- **Pause until** — snooze for maintenance windows; the monitor reactivates by itself.

Transitions (down/up) appear as alerts in the «Statistics» tab and are e-mailed to administrators who
opted into monitoring notifications on their profile (a separate opt-in from the access-pattern alerts).
Mails go out on transitions only — a lasting outage does not spam. Evaluation runs every
`Keyward:Monitoring:CheckIntervalSeconds` (default 60, `Enabled` is the kill-switch); statistics
persistence is batched, so silence thresholds under about two flush intervals are not meaningful.

### The explicit ping

`GET /ping` authenticates the token and does nothing else — reaching the endpoint is what records the
access. `Am.Keyward.Client` exposes it as `KeywardSecretsClient.PingAsync()`. Two situations call for it:

- **A long-running service** reads its secrets once at startup and would look silent for days: ping on a
  timer (e.g. every minute) and set the monitor's maximum silence accordingly.
- **A scheduled job** pings at the **end of a successful run**. That says more than the implicit heartbeat
  of its startup secret read, because it proves the run *completed* rather than merely started — a job that
  starts and then dies goes down too.

For a scheduled job, `KeywardHeartbeat` is the whole thing — no DI container, no `try`/`catch` of your own:

```csharp
// Last statement of a run that completed. Reads Keyward:ServiceUri from configuration; the token comes
// from KEYWARD_CONTOSO_NIGHTLY_SYNC_TOKEN on this machine.
await KeywardHeartbeat.SendAsync(configuration, "Contoso.Nightly.Sync", logger);
```

It is best-effort by contract and returns whether the heartbeat actually landed: an absent or empty
`Keyward:ServiceUri` means monitoring is off for this environment (the usual local-development case), and
a missing token, an unreachable server or a revoked token are logged and reported as `false` rather than
thrown. A monitoring outage must never turn into a job failure — the missing ping is itself the signal,
and it clears on the next successful run. Overloads take an explicit `Uri?` instead of `IConfiguration`,
or an `Action<KeywardSecretsOptions>` for full control (explicit token, custom timeout, proxy handler).

For anything beyond the heartbeat, build the client directly; it owns its `HttpClient`, so dispose it:

```csharp
using var keyward = KeywardSecretsClient.Create(o =>
{
    o.ServiceUri = new Uri("https://keyward.example.com");
    o.ApplicationName = "Contoso.Nightly.Sync";
});
var connectionString = await keyward.GetAsync("ConnectionStrings:Main");
```

Note that pings count toward the token's request statistics like any other authenticated call.

One boundary is systemic: if the Keyward host itself is down, nobody evaluates the monitors. Watch the
host's `/health` endpoint with an external check (uptime monitor, PRTG, …) — that single probe covers the
watcher of everything else.

## Security notes

- Tokens carry no secret material at rest — only a SHA-256 hash and a non-secret lookup prefix are stored.
- The token determines the tenant scope server-side; reads are additionally constrained by the database
  row-level-security policy (see [database logins](database-logins.md)).
- The management API above requires a signed-in admin (the host's authorization policy), and the route's
  `{tenantId}` is verified against the signed-in user's tenant membership — non-members get 403 (system
  admins count as members of every tenant).
