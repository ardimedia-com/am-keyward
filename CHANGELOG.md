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
- Slice 2 (crypto) — explicit envelope encryption (`Am.Keyward.Infrastructure`): AES-256-GCM per value
  with a fresh 256-bit data key, full-slot AAD binding (`Aad`), DEK wrapping via `IKekProvider`
  (`StaticKekProvider`, AES-256-GCM wrap — BCL primitive in lieu of RFC-3394 AES-KW; recorded in
  `EncryptedValue.WrapAlg`), DEK zeroed after use. On-disk format frozen as `FormatVersion = 1`.
  Verified by round-trip, tamper-detection, slot-substitution and wrong-KEK tests.
- Slice 2 (persistence) — EF Core 10 / **Microsoft SQL Server**: `KeywardDbContext` (default schema
  `amkeyward`, schema-scoped migrations history), value conversions for `EncryptedValue` / `SecretKey` /
  `EnvironmentName`, the Initial migration and a design-time factory.
- Slice 3 (walking skeleton, core) — software-credentials vertical: `ISoftwareSecretService` (Core
  application) with an EF-backed implementation (encrypt-and-store / read-and-decrypt, full-slot AAD), a
  minimal per-tenant hash-chained `DbAuditSink`, and the `AddKeyward` DI registration. Proven by an
  end-to-end integration test (DI → SQL Server → encrypt/store → read/decrypt; value encrypted at rest;
  operations audited).
