# Changelog

All notable changes to this project are documented here, following
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The project is pre-1.0.

## [Unreleased]

### Added

- Initial solution skeleton (Slice 0): layered projects — `Am.Keyward.Core` (pure domain/application),
  `Am.Keyward.Infrastructure`, `Am.Keyward.Contracts`, `Am.Keyward.Api`, `Am.Keyward.Ui.Blazor` (RCL),
  `Am.Keyward.Ui.Blazor.App` (standalone reference shell), and `Am.Keyward.Tests`.
- `Directory.Build.props`, MIT `LICENSE`, `SECURITY.md`, end-user `docs/`, and GitHub Actions CI
  (build + test on .NET 10 / SQL Server).
- Slice 1 — core domain model (`Am.Keyward.Core`): aggregates (tenants, global users, tenant/group
  memberships; projects → runtime environments → software secrets → per-environment values →
  versions; vaults → folders → items → versions; access grants; audit entries), value objects
  (`EncryptedValue`, `SecretKey`, `EnvironmentName`, `GrantScope`) and ports. The domain is pure (no
  EF/ASP.NET/crypto references) and guarded by a NetArchTest architecture test.
