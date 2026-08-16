# Database logins

AM KEYWARD can use two database principals with different privileges, so the application that serves
secrets never holds the rights needed to alter the schema or to switch the isolation policy off. This is
**hardening, not a prerequisite** — see "What the split does and does not buy" below before you decide
whether the operational cost is worth it in your deployment.

| Login | Purpose | Privileges | Effect on the isolation policy |
|---|---|---|---|
| `amkeyward_migrator` | Applies schema migrations (DDL: tables, indexes, the RLS policy) | `db_owner` on `amkeyward` | May create, alter, disable or drop it — that is the point of the trusted migration step |
| `amkeyward_app` | Runtime access used by the application to read and write secrets | `SELECT/INSERT/UPDATE/DELETE` on the `amkeyward` schema only — **not** `db_owner` | May not touch it; the policy filters its queries |

## Why two logins

Tenant isolation is defended in two independent layers:

1. The application scopes every query to the current tenant (an EF Core global query filter).
2. SQL Server **row-level security** enforces the same boundary inside the database, using the
   `SESSION_CONTEXT('TenantId')` value the application sets on each connection.

### What the split does and does not buy

Layer 2 protects you **regardless of which login the runtime uses**. SQL Server applies a security
policy's filter predicates to *every* principal — `dbo`, the table owner, `db_owner` and `sysadmin`
included — unless the predicate function itself exempts them (e.g. `OR IS_MEMBER('db_owner') = 1`), and
AM KEYWARD's predicates do not. A privileged runtime connection therefore gets the **same** tenant and
personal-vault isolation as `amkeyward_app`. See
[Row-Level Security](https://learn.microsoft.com/en-us/sql/relational-databases/security/row-level-security):
*"If a dbo user, a member of the db_owner role, or the table owner queries a table that has a security
policy defined and enabled, the rows are filtered or blocked as defined by the security policy."*

What the least-privilege runtime login adds is narrower, and worth stating precisely: that connection
cannot **disable or drop** the policy, and cannot change the schema. It raises the bar for an attacker who
has gained the ability to run arbitrary SQL through the application but has not compromised the process
itself. Note that the stored data is encrypted under the KEK, so disabling the policy yields ciphertext,
and an attacker who owns the process holds the KEK anyway.

So: adopt the split where it is cheap — a dedicated AM KEYWARD database with its own logins, a deployment
that already manages secrets. Skip it where it would cost a password to create, deploy, rotate and recover
for that one benefit, for example when AM KEYWARD is **embedded** in a host's own database and the host
already connects with an integrated-security principal. Both configurations enforce tenant isolation; only
this one property differs, and the choice belongs to the operator rather than to this document.

## Creating the logins

Only needed if you adopt the split. Run [`db/setup-logins.sql`](../db/setup-logins.sql) once as a sysadmin,
after the `amkeyward` database exists and has been migrated. Replace the placeholder passwords first. The
script is idempotent.

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
