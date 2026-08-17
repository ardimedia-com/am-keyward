using Am.Keyward.Core.Abstractions;
using Am.Keyward.Infrastructure.Crypto;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;

namespace Am.Keyward.Infrastructure.Provisioning;

/// <summary>
/// Diagnoses whether AM KEYWARD is provisioned in THIS environment — the data behind a host's status page and
/// its startup check.
/// <para>
/// Two constraints shape this class. First, it must work when Keyward is <b>switched off</b>: a host that
/// registers no Keyward services at all still registers this one, because explaining a half-configured or
/// dormant environment is exactly its job. It therefore resolves nothing from the Keyward container — every
/// check reads configuration or talks to SQL directly. Second, it must <b>never surface a secret</b>: the
/// connection string is reported through <see cref="SqlConnectionStringBuilder"/> as server / database /
/// login only, never as the raw string.
/// </para>
/// <para>
/// It carries no prose either: each check reports an id and an outcome, and the UI turns those into
/// sentences in the viewer's language.
/// </para>
/// </summary>
public sealed class KeywardProvisioningStatusService(
    IConfiguration configuration,
    IOptions<KeywardProvisioningOptions> options,
    IKeywardHostEnvironment environment) : IKeywardProvisioningStatus
{
    #region Fields

    private const string SchemaProbeSql = "SELECT COUNT(1) FROM sys.schemas WHERE name = @schema";

    private readonly KeywardProvisioningOptions options = options.Value;

    #endregion

    #region Properties

    /// <summary>The host's master switch, as passed in.</summary>
    public bool Enabled => this.options.Enabled;

    /// <summary>Name of the running environment, so a page can say which install it is describing.</summary>
    public string EnvironmentName => environment.EnvironmentName;

    /// <summary>Whether Keyward is meant to run here (the host's policy; Development optional by default).</summary>
    public KeywardExpectation Expectation =>
        this.options.Expectation?.Invoke(environment)
        ?? (environment.IsDevelopment ? KeywardExpectation.Optional : KeywardExpectation.Required);

    /// <summary>
    /// The settings file that carries THIS environment's values: the base <c>appsettings.json</c> is the
    /// Development overlay, every other tier has its own <c>appsettings.{Environment}.json</c>. Used to tell
    /// the operator exactly which file to edit.
    /// </summary>
    public string SettingsFile =>
        environment.IsDevelopment ? "appsettings.json" : $"appsettings.{this.EnvironmentName}.json";

    /// <summary>The configuration key of the runtime connection string, for the "which key?" hint.</summary>
    public string ConnectionStringName => this.options.ConnectionStringName;

    /// <summary>
    /// The full path of the KEK file, or <c>null</c> when there is none to check — either because the host
    /// uses an external key provider, or because this is not Windows (the packaged file custody is DPAPI).
    /// </summary>
    public string? KekPath =>
        OperatingSystem.IsWindows() && this.options.KekDirectory is { Length: > 0 } directory
            ? Path.Combine(directory, DpapiKekFile.FileName)
            : null;

    /// <summary>
    /// Server + database of the Keyward connection, for naming the "other half" of the backup on a page.
    /// Server and catalog only — never the raw string, which may carry a password.
    /// </summary>
    public string? DatabaseLabel
    {
        get
        {
            string? connectionString = configuration.GetConnectionString(this.options.ConnectionStringName);
            if (string.IsNullOrWhiteSpace(connectionString))
            {
                return null;
            }

            try
            {
                SqlConnectionStringBuilder builder = new(connectionString);
                return $"{builder.DataSource} / {builder.InitialCatalog}";
            }
            catch
            {
                return null;
            }
        }
    }

    #endregion

    #region Public Methods

    /// <summary>
    /// Runs every check. Never throws — a probe that fails becomes a <see cref="KeywardCheckState.Missing"/>
    /// row carrying the provider's message, because a diagnostics page that crashes on a broken environment
    /// is useless exactly when it is needed.
    /// </summary>
    public async Task<IReadOnlyList<KeywardCheck>> RunAsync(CancellationToken cancellationToken = default)
    {
        List<KeywardCheck> checks = [this.CheckFeatureSwitch()];

        // When Keyward is off where that is acceptable, its provisioning sub-points are moot — reporting the
        // KEK, the connection string and the database as "missing" would be noise, not findings. Only when it
        // is ON, or off but REQUIRED here, do the remaining points matter.
        if (!this.Enabled && this.Expectation != KeywardExpectation.Required)
        {
            return checks;
        }

        checks.Add(this.CheckKekFile());

        string? connectionString = configuration.GetConnectionString(this.options.ConnectionStringName);
        checks.Add(CheckConnectionString(connectionString, environment.IsDevelopment));

        if (string.IsNullOrWhiteSpace(connectionString))
        {
            checks.Add(NotProbed(KeywardCheckId.DatabaseReachable));
            checks.Add(NotProbed(KeywardCheckId.Schema));
            checks.Add(NotProbed(KeywardCheckId.Tenant));
            return checks;
        }

        checks.AddRange(await this.ProbeDatabaseAsync(connectionString, cancellationToken).ConfigureAwait(false));
        return checks;
    }

    #endregion

    #region Private Methods

    private KeywardCheck CheckFeatureSwitch()
    {
        string technical = $"Keyward:Enabled = {(this.Enabled ? "true" : "false")}";

        if (this.Enabled)
        {
            return new KeywardCheck(KeywardCheckId.FeatureSwitch, KeywardCheckState.Ok, KeywardCheckOutcome.Ok, technical);
        }

        // Off is only a defect where Keyward is REQUIRED. Where it is optional or deliberately off, "off" is
        // the correct state and must not be reported as a gap.
        return this.Expectation == KeywardExpectation.Required
            ? new KeywardCheck(KeywardCheckId.FeatureSwitch, KeywardCheckState.Missing, KeywardCheckOutcome.FeatureOffRequired, technical)
            : new KeywardCheck(KeywardCheckId.FeatureSwitch, KeywardCheckState.Ok, KeywardCheckOutcome.FeatureOffAcceptable, technical);
    }

    private KeywardCheck CheckKekFile()
    {
        if (this.KekPath is not { } path)
        {
            // A KMS/HSM-backed host has no file to check; saying so beats reporting a missing file it never wanted.
            return new KeywardCheck(KeywardCheckId.KekFile, KeywardCheckState.Ok, KeywardCheckOutcome.KekNotFileBased);
        }

        return File.Exists(path)
            ? new KeywardCheck(KeywardCheckId.KekFile, KeywardCheckState.Ok, KeywardCheckOutcome.Ok, path)
            : new KeywardCheck(KeywardCheckId.KekFile, KeywardCheckState.Missing, KeywardCheckOutcome.KekMissing, path);
    }

    /// <summary>
    /// Reports the connection target WITHOUT the raw string: server, database and login only. A malformed
    /// string is reported as such rather than echoed back, because it may carry a password.
    /// </summary>
    private static KeywardCheck CheckConnectionString(string? connectionString, bool isDevelopment)
    {
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            return new KeywardCheck(KeywardCheckId.ConnectionString, KeywardCheckState.Missing, KeywardCheckOutcome.ConnectionMissing);
        }

        try
        {
            SqlConnectionStringBuilder builder = new(connectionString);
            string login = builder.IntegratedSecurity
                ? "Integrated Security"
                : string.IsNullOrEmpty(builder.UserID) ? "(no user)" : builder.UserID;
            string technical = $"{builder.DataSource} / {builder.InitialCatalog} · {login}";

            // Integrated Security outside Development is REPORTED, not faulted. It used to be a Warning on the
            // premise that only a least-privilege login makes row-level security bite — which is wrong: SQL
            // Server applies a security policy's filter predicates to every principal, db_owner included, so
            // tenant and vault isolation hold either way. A dedicated login withholds one narrower thing (the
            // right to DISABLE the policy or alter the schema), which is worthwhile hardening but a posture the
            // operator chooses, not a gap to close. A status page may only flag what somebody must do; listing
            // a deliberate, documented choice as an open point is how a page stops being read at all.
            return builder.IntegratedSecurity && !isDevelopment
                ? new KeywardCheck(KeywardCheckId.ConnectionString, KeywardCheckState.Ok,
                    KeywardCheckOutcome.ConnectionIntegratedSecurityOutsideDevelopment, technical)
                : new KeywardCheck(KeywardCheckId.ConnectionString, KeywardCheckState.Ok, KeywardCheckOutcome.Ok, technical);
        }
        catch (Exception ex)
        {
            return new KeywardCheck(KeywardCheckId.ConnectionString, KeywardCheckState.Missing,
                KeywardCheckOutcome.ConnectionUnreadable, Error: ex.Message);
        }
    }

    /// <summary>Opens the connection once and runs the schema / migration / tenant probes over it.</summary>
    private async Task<List<KeywardCheck>> ProbeDatabaseAsync(string connectionString, CancellationToken cancellationToken)
    {
        List<KeywardCheck> checks = [];

        string? target;
        try
        {
            SqlConnectionStringBuilder builder = new(connectionString);
            target = $"{builder.DataSource} / {builder.InitialCatalog}";
        }
        catch
        {
            target = null;
        }

        await using SqlConnection connection = new(connectionString);
        try
        {
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            checks.Add(new KeywardCheck(KeywardCheckId.DatabaseReachable, KeywardCheckState.Ok, KeywardCheckOutcome.Ok, target));
        }
        catch (Exception ex)
        {
            checks.Add(new KeywardCheck(KeywardCheckId.DatabaseReachable, KeywardCheckState.Missing,
                KeywardCheckOutcome.DatabaseUnreachable, target, ex.Message));
            checks.Add(NotProbed(KeywardCheckId.Schema));
            checks.Add(NotProbed(KeywardCheckId.Tenant));
            return checks;
        }

        bool schemaExists;
        try
        {
            await using SqlCommand probe = new(SchemaProbeSql, connection);
            probe.Parameters.AddWithValue("@schema", KeywardDbContext.Schema);
            schemaExists = Convert.ToInt32(await probe.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false)) > 0;
        }
        catch
        {
            schemaExists = false;
        }

        if (!schemaExists)
        {
            checks.Add(new KeywardCheck(KeywardCheckId.Schema, KeywardCheckState.Missing, KeywardCheckOutcome.SchemaMissing,
                KeywardDbContext.Schema));
            checks.Add(NotProbed(KeywardCheckId.Tenant));
            return checks;
        }

        try
        {
            await using SqlCommand probe = new(
                $"SELECT COUNT(1) FROM [{KeywardDbContext.Schema}].[__EFMigrationsHistory]", connection);
            int migrations = Convert.ToInt32(await probe.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false));
            checks.Add(migrations > 0
                ? new KeywardCheck(KeywardCheckId.Schema, KeywardCheckState.Ok, KeywardCheckOutcome.Ok,
                    $"{KeywardDbContext.Schema} · {migrations}")
                : new KeywardCheck(KeywardCheckId.Schema, KeywardCheckState.Missing, KeywardCheckOutcome.SchemaNoMigrations,
                    $"{KeywardDbContext.Schema} · 0"));
        }
        catch (Exception ex)
        {
            checks.Add(new KeywardCheck(KeywardCheckId.Schema, KeywardCheckState.Missing, KeywardCheckOutcome.SchemaUnreadable,
                KeywardDbContext.Schema, ex.Message));
        }

        checks.Add(await this.ProbeTenantAsync(connection, cancellationToken).ConfigureAwait(false));
        return checks;
    }

    /// <summary>
    /// Checks the host's tenant row. Keyward enforces row-level security, so the row is only visible once
    /// <c>SESSION_CONTEXT('TenantId')</c> is set — exactly what the app does per request/circuit. Without
    /// setting it first the probe would read 0 rows and report a missing seed that is actually there.
    /// </summary>
    private async Task<KeywardCheck> ProbeTenantAsync(SqlConnection connection, CancellationToken cancellationToken)
    {
        string technical = $"{this.options.TenantName} · {this.options.TenantId}";
        try
        {
            await using (SqlCommand scope = new("EXEC sp_set_session_context @key = N'TenantId', @value = @tenantId", connection))
            {
                scope.Parameters.AddWithValue("@tenantId", this.options.TenantId);
                await scope.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }

            await using SqlCommand probe = new(
                $"SELECT COUNT(1) FROM [{KeywardDbContext.Schema}].[Tenants] WHERE Id = @tenantId", connection);
            probe.Parameters.AddWithValue("@tenantId", this.options.TenantId);
            int count = Convert.ToInt32(await probe.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false));

            return count > 0
                ? new KeywardCheck(KeywardCheckId.Tenant, KeywardCheckState.Ok, KeywardCheckOutcome.Ok, technical)
                : new KeywardCheck(KeywardCheckId.Tenant, KeywardCheckState.Missing, KeywardCheckOutcome.TenantMissing, technical);
        }
        catch (Exception ex)
        {
            return new KeywardCheck(KeywardCheckId.Tenant, KeywardCheckState.Missing, KeywardCheckOutcome.TenantUnreadable,
                technical, ex.Message);
        }
    }

    private static KeywardCheck NotProbed(KeywardCheckId id) =>
        new(id, KeywardCheckState.Missing, KeywardCheckOutcome.NotProbed);

    #endregion
}
