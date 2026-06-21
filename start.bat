@echo off
REM ============================================================================
REM  Start the AM KEYWARD standalone reference shell locally.
REM
REM  Environment : Development
REM  URL         : https://localhost:7212  (open /secrets for the demo page)
REM  Mode        : dotnet watch -> code/markup changes hot-reload automatically
REM
REM  Press Ctrl+C to stop.
REM
REM  NOTE: dotnet watch hot-reloads CODE, not appsettings/config. After changing
REM        appsettings*.json or IOptions values, stop (Ctrl+C) and start again.
REM
REM  PREREQUISITES (handled automatically unless noted):
REM    - .NET 10 SDK.
REM    - A trusted ASP.NET Core HTTPS dev certificate. If the browser shows a
REM      certificate warning on first start, run once:
REM          dotnet dev-certs https --trust
REM    - A local SQL Server reachable on "localhost" via Integrated Security.
REM      The database "amkeyward" is created + migrated on startup and a demo
REM      tenant/project (Dev/Test/Preview/Production) is seeded automatically.
REM      To reset, drop the "amkeyward" database; startup recreates it.
REM    - A dev KEK is auto-created as "kek.dev.key" in the shell folder
REM      (gitignored, kept OUTSIDE the database). Production uses a real KEK
REM      provider (Azure Key Vault / HSM) instead -- see SECURITY.md.
REM ============================================================================
REM
REM  TESTING:
REM    Automated tests (unit + integration). The integration / end-to-end tests
REM    talk to the local "amkeyward" SQL Server; they self-skip (Inconclusive)
REM    when no DB is reachable, so they stay green on a machine without SQL.
REM        dotnet test Am.Keyward.slnx
REM
REM    First run: open https://localhost:7212 -> you are redirected to sign in.
REM    Register the first account; it becomes the system administrator.
REM
REM    Manual UI smoke test (signed in):
REM      - /vaults  : create a personal vault, add folders/items, reveal a value.
REM      - /secrets : store and read a value (demo project, per environment).
REM      - /tokens  : issue / rotate / revoke software-client tokens (shown once).
REM
REM    Manual software-client API test (PowerShell). The client read API is
REM    token-authenticated + rate limited; the scope (tenant/project/environment)
REM    comes from the token. Issue a token on the /tokens page, then:
REM
REM      $base = "https://localhost:7212/keyward/api/v1"
REM      $h = @{ Authorization = "Bearer <paste-token-from-/tokens>" }
REM      Invoke-RestMethod -Uri "$base/secrets" -Headers $h                        # all keys
REM      Invoke-RestMethod -Uri "$base/secrets/ConnectionStrings:Main" -Headers $h # one key
REM
REM    (A trusted dev cert lets Invoke-RestMethod use https directly; otherwise add
REM    -SkipCertificateCheck on PowerShell 7+.) The management API
REM    (/keyward/api/v1/tenants/...) now requires a signed-in admin (cookie), so use
REM    the UI above to create secrets and issue tokens.
REM
REM    Tenant isolation is active (EF query filter + SQL Server row-level security).
REM    Local dev uses Integrated Security and needs no extra logins. To also verify
REM    RLS against the least-privilege runtime login, create the two logins from
REM    db\setup-logins.sql and point the test at the app connection (see
REM    docs\database-logins.md):
REM        setx KEYWARD_APP_TEST_CONNECTION "Server=localhost;Database=amkeyward;User Id=amkeyward_app;Password=...;Encrypt=False"
REM ============================================================================
REM
REM  STILL TODO (open work -- this is a v0.1 walking skeleton, not finished):
REM    [Slice 6] Tenant/group vaults + "Shared" (grant-based sharing within a
REM              tenant). [Admin sign-in, the My Vault UI + shell theme, and the
REM              token-management page have landed.]
REM    [Slice 7] Ops hardening: audit hash-chain (DB SEQUENCE/single-writer/
REM              exported checkpoint), DSGVO crypto-shredding, backup/restore
REM              consistency, DB-swap safety-net migrator, monitoring, break-glass.
REM    [Slice 8] Docs / KEK+DR runbook / tag-driven release.
REM    [v0.2]    Opt-in zero-knowledge vaults (browser WebCrypto) -- gated on an
REM              external security review.
REM    [Manual]  Upload .github\social-preview.png under GitHub repo
REM              Settings -> Social preview (cannot be set via git/API).
REM ============================================================================

setlocal
cd /d "%~dp0"

set ASPNETCORE_ENVIRONMENT=Development

dotnet watch --project "src\Am.Keyward.Ui.Blazor.App\Am.Keyward.Ui.Blazor.App.csproj" --launch-profile https

endlocal
