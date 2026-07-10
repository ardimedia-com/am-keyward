# Database logins

AM KEYWARD uses two database principals with different privileges, so the application that serves
secrets never holds the rights needed to alter the schema or to switch off tenant isolation.

| Login | Purpose | Privileges | Row-level security |
|---|---|---|---|
| `amkeyward_migrator` | Applies schema migrations (DDL: tables, indexes, the RLS policy) | `db_owner` on `amkeyward` | Bypassed (db_owner) — correct for the trusted migration step |
| `amkeyward_app` | Runtime access used by the application to read and write secrets | `SELECT/INSERT/UPDATE/DELETE` on the `amkeyward` schema only — **not** `db_owner` | Enforced — cannot read or write another tenant's rows |

## Why two logins

Tenant isolation is defended in two independent layers:

1. The application scopes every query to the current tenant (an EF Core global query filter).
2. SQL Server **row-level security** enforces the same boundary inside the database, using the
   `SESSION_CONTEXT('TenantId')` value the application sets on each connection.

Layer 2 only protects you if the runtime login cannot bypass it. Members of `db_owner` (and `sysadmin`)
bypass RLS, so the runtime must use a login that is **not** one of those — that is `amkeyward_app`. The
migrator needs full DDL rights (it creates the RLS policy itself), so it is `db_owner`; it is used only
for migrations, never to serve requests.

## Creating the logins

Run [`db/setup-logins.sql`](../db/setup-logins.sql) once as a sysadmin, after the `amkeyward` database
exists and has been migrated. Replace the placeholder passwords first. The script is idempotent.

```
sqlcmd -S localhost -E -i db/setup-logins.sql
```

Where Windows authentication or a managed identity is available, prefer that over SQL passwords: create
a user for that principal and give it the same role membership / schema permissions shown above.

## Which connection uses which login

- **Migrations** (the deploy step, or the reference shell's startup migrate) use the **migrator** login.
- **The running application** uses the **app** login.

```
# migrator (DDL)
Server=<host>;Database=amkeyward;User Id=amkeyward_migrator;Password=...;Encrypt=True

# app (runtime)
Server=<host>;Database=amkeyward;User Id=amkeyward_app;Password=...;Encrypt=True
```

### Migrating from the host

A host can apply the schema migrations at startup through the migrator connection with the
`KeywardSchemaMigrator` helper, instead of building a `KeywardDbContext` itself:

```csharp
await KeywardSchemaMigrator.MigrateAsync(migratorConnectionString);   // DDL-capable connection
```

The runtime still registers `AddKeyward(...)` with the **app** connection, so row-level security stays
enforced. When the `amkeyward` schema is **embedded in the host's own database** (a shared database rather
than a dedicated `amkeyward` one), the migrator connection is simply the host's existing privileged
connection to that database — no separate migrator login is required. It is idempotent and safe to call on
every start; wrap it so a failure degrades AM KEYWARD to "unavailable" rather than crashing the host.

## Local development

Local development uses Integrated Security, which can both migrate and run, so you do not need these
logins to work on AM KEYWARD. They exist for production-like privilege separation and to verify RLS end
to end. The integration tests take care of this themselves: the test bootstrap migrates the dedicated
**`amkeywardtest`** database and runs `db/setup-logins.sql` against it (generated passwords), so the
row-level-security test runs out of the box. `KEYWARD_APP_TEST_CONNECTION` is only an optional override
if you want the RLS test to use a login/database you provisioned yourself; the tests' base connection
string can be overridden via `ConnectionStrings__Keyward`.
