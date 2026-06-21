/*
    AM KEYWARD — database logins (template)

    Creates the two-login setup for the `amkeyward` database:

      amkeyward_migrator  Applies schema migrations (DDL: tables, indexes, the row-level-security
                          policy). Member of db_owner; being db_owner it bypasses RLS, which is correct
                          for the trusted migration step.

      amkeyward_app       Runtime application access (DML only: SELECT/INSERT/UPDATE/DELETE). It is
                          deliberately NOT db_owner, so SQL Server row-level security is ENFORCED against
                          it — a buggy or hostile query still cannot read another tenant's rows.

    The runtime sets the SESSION_CONTEXT key 'TenantId' on each connection (see the application's
    TenantSessionContextInterceptor); the RLS policy uses it to admit only the current tenant's rows.

    How to run
      1. Make sure the `amkeyward` database exists and migrations have been applied at least once.
      2. Replace the two placeholder passwords below.
      3. Execute this script once as a sysadmin (sqlcmd or SSMS), e.g.:
             sqlcmd -S localhost -E -i db/setup-logins.sql

    Notes
      - These are SQL logins, for environments without Windows authentication (containers, Linux SQL
        Server). Where Windows auth or a managed identity is available, prefer that and just grant the
        same database-role membership / schema permissions to that principal instead.
      - Local development uses Integrated Security, which can both migrate and run; these two logins are
        for production-like separation and to exercise RLS end to end (see docs/database-logins.md).
*/

USE master;
GO

IF SUSER_ID(N'amkeyward_migrator') IS NULL
    CREATE LOGIN [amkeyward_migrator] WITH PASSWORD = N'<set-a-strong-migrator-password>', CHECK_POLICY = ON;
GO

IF SUSER_ID(N'amkeyward_app') IS NULL
    CREATE LOGIN [amkeyward_app] WITH PASSWORD = N'<set-a-strong-app-password>', CHECK_POLICY = ON;
GO

USE amkeyward;
GO

-- Migrator: full DDL rights for migrations.
IF USER_ID(N'amkeyward_migrator') IS NULL
    CREATE USER [amkeyward_migrator] FOR LOGIN [amkeyward_migrator];
GO
IF IS_ROLEMEMBER(N'db_owner', N'amkeyward_migrator') = 0
    ALTER ROLE [db_owner] ADD MEMBER [amkeyward_migrator];
GO

-- Application: least privilege — DML on the amkeyward schema only, never db_owner (so RLS applies).
IF USER_ID(N'amkeyward_app') IS NULL
    CREATE USER [amkeyward_app] FOR LOGIN [amkeyward_app];
GO
GRANT SELECT, INSERT, UPDATE, DELETE ON SCHEMA::[amkeyward] TO [amkeyward_app];
GO
