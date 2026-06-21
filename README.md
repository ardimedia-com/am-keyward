# AM KEYWARD

> ⚠️ **Early development (pre-1.0).** Not production-ready. The security design has **not** yet been
> externally reviewed — do not store real secrets in it yet.

**AM KEYWARD** is an open-source, .NET-native, **library-first** credential & secrets manager: a
building block you embed in your own .NET environment (and can offer to your own users), plus an
optional **standalone reference app**.

It covers two halves equally:

- **Software credentials** — machine/integration secrets (API keys, connection strings), scoped per
  project & environment, fetched by your software via an API.
- **Human vaults** — personal & team password vaults, shared to groups or individuals.

## What it is / is not

- **Is:** an embeddable toolkit + reference app that you self-host and operate.
- **Is not:** a hosted service, and not a HashiCorp-Vault-at-scale replacement.

There is no central, vendor-hosted AM KEYWARD. **Each operator runs and secures their own deployment**
(key custody, database, hardening) — see [SECURITY.md](SECURITY.md).

## Tech

.NET 10 · Blazor Server · ASP.NET Core · EF Core (Microsoft SQL Server) · MIT licensed.

## Build

```
dotnet build Am.Keyward.slnx
dotnet test Am.Keyward.slnx
```

Requires the .NET 10 SDK; data/integration tests require SQL Server (LocalDB).

## Documentation

End-user & operator documentation lives in [`docs/`](docs/) and grows as features ship.

## License

[MIT](LICENSE) © 2026 Ardimedia Anstalt
