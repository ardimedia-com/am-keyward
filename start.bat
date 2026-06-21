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
REM  STILL TODO (open work -- this is a v0.1 walking skeleton, not finished):
REM    [Slice 4] Multi-tenancy + isolation: global users + 0..n tenants, the
REM              composite query filter + SQL Server RLS (SESSION_CONTEXT), a
REM              least-privilege runtime SQL login separate from migrations, the
REM              adversarial cross-tenant test gate, and the central
REM              IAuthorizationService. (RLS is NOT active yet.)
REM    [Slice 5] Software-client API auth: per-(project,environment) tokens
REM              (expiry/rotation/revocation + notifications) + rate limiting.
REM              WARNING: the API at /keyward/api/v1 is currently UNAUTHENTICATED
REM              -- do NOT expose this build off localhost.
REM    [Slice 6] Human vaults UI (My Vault / Shared) + folders + sharing.
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
