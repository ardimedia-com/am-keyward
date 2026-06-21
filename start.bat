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
REM    Manual UI smoke test:
REM        Open https://localhost:7212/secrets and use the demo page to store
REM        and read a value (the demo tenant/project below are pre-seeded).
REM
REM    Manual API smoke test (PowerShell). Two surfaces:
REM      - Management API (route-scoped): create secrets + issue tokens. Still
REM        UNAUTHENTICATED pending the human admin sign-in slice.
REM      - Software-client API (token-authenticated, rate limited): read secrets.
REM      Demo tenant  = 11111111-1111-1111-1111-111111111111
REM      Demo project = 22222222-2222-2222-2222-222222222222
REM    A trusted dev cert (see above) lets Invoke-RestMethod use https directly;
REM    otherwise add -SkipCertificateCheck (PowerShell 7+).
REM
REM      $base   = "https://localhost:7212/keyward/api/v1"
REM      $proj   = "$base/tenants/11111111-1111-1111-1111-111111111111" +
REM                "/projects/22222222-2222-2222-2222-222222222222"
REM
REM      # 1) Store a secret via the management API (PUT -> 204):
REM      Invoke-RestMethod -Method Put -ContentType "application/json" `
REM          -Uri "$proj/environments/Production/secrets/ConnectionStrings:Main" `
REM          -Body '{ "value": "Server=db;User Id=app;Password=hunter2" }'
REM
REM      # 2) Issue a software-client token for Production (returns the token ONCE):
REM      $issued = Invoke-RestMethod -Method Post -ContentType "application/json" `
REM          -Uri "$proj/environments/Production/tokens" -Body '{ "name": "demo" }'
REM
REM      # 3) Read as the software client (Bearer token; scope comes from the token):
REM      $headers = @{ Authorization = "Bearer $($issued.token)" }
REM      Invoke-RestMethod -Uri "$base/secrets" -Headers $headers                       # all keys
REM      Invoke-RestMethod -Uri "$base/secrets/ConnectionStrings:Main" -Headers $headers # one key
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
REM    WARNING: the MANAGEMENT API (/keyward/api/v1/tenants/...) is still
REM             UNAUTHENTICATED pending the human admin sign-in slice -- do NOT
REM             expose this build off localhost. (The software-client read API is
REM             token-authenticated and rate limited.)
REM    [Slice 6] Human admin sign-in + vaults UI (My Vault / Shared) + folders +
REM              sharing; protects the management API + a token-management page.
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
