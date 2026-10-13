# keyward — the command line for scripts and tools

`keyward` reads secrets from AM KEYWARD for scripts, scheduled tasks, MCP servers and PowerShell. It uses the
[software-client API](software-client-api.md) with an **app token** — one token per consumer application and
environment, issued under *Applications → Tokens* — and keeps that token in the **Windows Credential Manager** or
the **macOS Keychain**, never in a file.

It is the counterpart of `amkeyward-mcp` (the [agent API and MCP server](agent-api.md)): `amkeyward-mcp` lets an AI
assistant work **as you** with an agent token; `keyward` lets a **program** read the values of one application with
an app token. The two never share a token: `keyward login` refuses an agent token (`amkwa_…`).

## Install

```powershell
dotnet tool install --global Am.Keyward.Cli --prerelease
keyward version
```

Computers without the .NET SDK take the single program file for their platform from the GitHub Release
(`keyward-win-x64.exe`, `keyward-osx-arm64.tar.gz`, …) and rename it to `keyward` (`keyward.exe` on Windows)
somewhere on the `PATH`. Each file has a `.sha256` next to it.

## Profiles

A **profile** is a name for one app token on this computer: `ops`, `prtg-prod`, `backup`. The profile file
(`%APPDATA%\Keyward\profiles.json`, `~/.config/keyward/profiles.json` elsewhere) only maps names to installations;
the token sits in the OS store under `AmKeyward:App:<profile>`.

```powershell
keyward login ops --service https://keyward.example.com   # paste the token (shown as *)
keyward profiles                                          # names, installations, whether a token is stored
keyward logout ops                                        # forgets profile and token on this computer
```

`login` checks the token against `/ping` before it stores anything. For automation pipe the token in with
`--token-stdin` (it is never accepted as an argument — arguments are visible in the process list).

Where there is no OS store (Linux, a container) the profile comes from environment variables:
`KEYWARD_PROFILE_<NAME>_SERVICE` and `KEYWARD_PROFILE_<NAME>_TOKEN` (`<NAME>` upper case, `-` and `.` as `_`).

## Reading values

A secret is addressed as `<profile>:<key>`; the key may contain colons (`ops:ConnectionStrings:Main`).

```powershell
keyward get ops:Prtg:ApiToken          # the value on stdout, nothing else
keyward get ops:Prtg:ApiToken --json   # {"key":"Prtg:ApiToken","value":"…"} — for callers that parse
keyward keys ops                       # the keys this token can read, never values
```

### Start one program with values — `keyward run`

The values go into the environment of **that program only** and disappear with it:

```powershell
keyward run --env PRTG_TOKEN=ops:Prtg:ApiToken -- python sync.py
keyward run --all ops --prefix OPS_ -- pwsh -File backup.ps1   # every key of the profile; ':' becomes '__'
```

`keyward` waits for the program and returns its exit code; Ctrl+C reaches the program.

### MCP servers in Claude Code

**Never wrap the AI agent itself** (`keyward run -- claude`): its shell could print the values into the
conversation (decision T20 A). Wrap a **single MCP server**, or let Claude Code ask for the header:

```powershell
# a local (stdio) MCP server that reads its token from the environment
claude mcp add --scope user prtg -- keyward run --env PRTG_TOKEN=ops:Prtg:ApiToken -- prtg-mcp
```

```json
{
  "mcpServers": {
    "prtg": {
      "type": "http",
      "url": "https://prtg.example.com/mcp",
      "headersHelper": "keyward headers --set \"Authorization=Bearer {ops:Prtg:ApiToken}\""
    }
  }
}
```

`keyward headers` prints the JSON object Claude Code expects. Claude Code runs it per connection and again after a
401/403, so a rotated value is picked up without a restart. Put such servers in the **user** scope: a project
`.mcp.json` is shared with everyone who clones the repository.

### A whole shell session — `keyward env`

```powershell
keyward env ops | Invoke-Expression          # PowerShell
eval "$(keyward env ops --shell sh)"         # sh / bash / zsh
```

The values then stay in the session until it ends — prefer `keyward run` where one program is enough.

## PowerShell

```powershell
keyward powershell install                   # PowerShell 7; --windows-powershell for 5.1, --path for a folder
Install-Module Microsoft.PowerShell.SecretManagement -Scope CurrentUser
Register-SecretVault -Name Keyward -ModuleName Am.Keyward.SecretManagement -VaultParameters @{ Profile = 'ops' }

Get-Secret -Vault Keyward -Name 'Prtg:ApiToken' -AsPlainText
Get-SecretInfo -Vault Keyward                 # the keys
```

The vault is **read-only**: values are maintained in Keyward. Each registered vault is one profile. Without
SecretManagement, the module's own command does the same:

```powershell
$token = Get-KeywardSecret -Profile ops -Name Prtg -Field token -AsPlainText     # key Prtg:Token
$cred  = Get-KeywardSecret -Profile ops -Name Prtg -AsCredential                 # Prtg:Username + Prtg:Password
```

A credential is stored as typed keys (`<Name>:Username`, `<Name>:Password`, `<Name>:Token`) — never parsed out of
text. The module calls `keyward` for every read (set `KEYWARD_EXE` to use a program that is not on the `PATH`).

## Moving a plain-text secrets file into Keyward — `keyward import`

A file of secrets in plain text (notes, a `.local.md`) is moved into application keys **without the values passing
through an AI agent** (decision T30 A). An agent may write the **mapping** — it holds no values — while `keyward`
reads the file locally:

```json
{
  "entries": [
    { "pattern": "^PRTG API token: `(?<value>[^`]+)`$",
      "application": "Ops.Prtg", "environment": "Production", "key": "Prtg:ApiToken" }
  ]
}
```

```powershell
keyward import --service https://keyward.example.com --mapping map.json --source notes.local.md --dry-run
keyward import --service https://keyward.example.com --mapping map.json --source notes.local.md
```

Each pattern must match **exactly one line** and capture the value in the group `value`; an entry matching no line
or several lines stops the whole import before anything is written. `--dry-run` shows line, target and length,
never the value. Existing values are kept unless `--overwrite` is given (the write uses `If-None-Match: *` /
`If-Match`, so a concurrent change is not overwritten silently).

Writing goes through the agent API with the agent token `amkeyward-mcp setup` stored for that installation (or
`KEYWARD_AGENT_TOKEN`); it needs the permission **«Manage applications»** and must reach the application. Delete the
plain-text file once every consumer reads from Keyward.

## Exit codes and errors

Errors go to stderr, prefixed `keyward:`; stdout carries only the requested output.

| Code | Meaning |
|---|---|
| 0 | OK (`run`: the program's own exit code) |
| 1 | Other failure |
| 2 | Usage — wrong arguments, or an import mapping with problems |
| 3 | No profile, or no token stored for it |
| 4 | Token rejected (revoked, expired, wrong installation) |
| 5 | Network not allowed (`Keyward:Client:AllowedNetworks`) |
| 6 | Unknown key — the application has no such key |
| 7 | No value — the key exists, but has no value in the token's environment |
| 8 | Keyward unreachable (5 s timeout; 30 s for `import`) |

6 and 7 come from the `reason` of the API's 404 answer (`unknown-key` / `no-value`).

## Security notes

- **No cache** (decision T22 A): every call asks Keyward, so a revoked token or a rotated value takes effect at once.
- Values never appear as **arguments** (visible in the process list): they go to stdout, into a child's environment,
  or as JSON to PowerShell.
- **Audit per read** (decision T23 A): tick *Log every read in the audit trail* on the app token (Applications →
  Tokens → token detail). Every single-key read with that token — `get`, `run --env`, `headers`, `Get-Secret` — then writes an audit
  entry with the key. A bulk read (`keys`, `run --all`, `env`) always writes one entry. Without the flag, single
  reads only update the token's access statistics.
- Limit the app token to its networks with `Keyward:Client:AllowedNetworks` on the host, and give each consumer
  application its own token, so one can be revoked without touching the others.
