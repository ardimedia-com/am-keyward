using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Infrastructure.Auth;
using Am.Keyward.Infrastructure.Crypto;
using Am.Keyward.Infrastructure.Persistence;
using Am.Keyward.Infrastructure.Tenancy;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Am.Keyward.Infrastructure;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers AM KEYWARD against a SQL Server database with an in-memory KEK (file/env-loaded by the host).
    /// Convenience overload for the reference shell / dev; production hosts that keep the KEK in a KMS/HSM
    /// should use the <see cref="AddKeyward(IServiceCollection, string, Func{IServiceProvider, IKekProvider})"/>
    /// overload so the raw key never has to enter the host process.
    /// </summary>
    public static IServiceCollection AddKeyward(this IServiceCollection services, string connectionString, byte[] kek, string kekId) =>
        services.AddKeyward(connectionString, _ => new StaticKekProvider(kek, kekId));

    /// <summary>
    /// Registers AM KEYWARD against a SQL Server database with a caller-supplied <see cref="IKekProvider"/>
    /// (e.g. an Azure Key Vault / AWS KMS / HSM-backed provider), so the key-encryption key can stay in the
    /// external key store and never enter the application process. The migrations-history table is scoped to
    /// the <c>amkeyward</c> schema so it never collides with the host's migrations. Tenant isolation is wired
    /// up here: the ambient tenant context, the SESSION_CONTEXT interceptor (row-level-security backstop) and
    /// the central authorization service.
    /// </summary>
    public static IServiceCollection AddKeyward(
        this IServiceCollection services, string connectionString, Func<IServiceProvider, IKekProvider> kekProviderFactory)
    {
        // One ambient tenant context per scope, exposed as both the read port (ICurrentTenant) and the
        // host-edge write port (ITenantScopeSetter).
        services.AddScoped<AmbientTenantContext>();
        services.AddScoped<ICurrentTenant>(sp => sp.GetRequiredService<AmbientTenantContext>());
        services.AddScoped<ITenantScopeSetter>(sp => sp.GetRequiredService<AmbientTenantContext>());

        // One ambient user context per scope, exposed as the read port (ICurrentUser) and the host-edge
        // write port (IUserScopeSetter). The host may override ICurrentUser (e.g. an HttpContext-backed one).
        services.AddScoped<AmbientUserContext>();
        services.AddScoped<ICurrentUser>(sp => sp.GetRequiredService<AmbientUserContext>());
        services.AddScoped<IUserScopeSetter>(sp => sp.GetRequiredService<AmbientUserContext>());

        services.AddScoped<IKeywardAccessPolicy, TenantAuthorizationService>();
        services.AddScoped<ITenantMembership, TenantMembershipService>();

        // The host-identity binding (just-in-time AppUser + tenant membership from the host's own access
        // model). It runs on the host's AUTHENTICATION path, so it deliberately needs no tenant scope: the
        // Users and TenantMemberships tables are installation-global.
        services.AddScoped<IKeywardIdentityBinder, KeywardIdentityBinder>();
        services.AddScoped<IGroupService, GroupService>();
        services.AddScoped<SystemReadScope>();
        services.AddScoped<TenantSessionContextInterceptor>();
        services.AddScoped<AuditChainInterceptor>();
        services.AddSingleton<ChangeTrackerResetInterceptor>();

        // A SCOPED factory (not the singleton default): the context constructor and the interceptors carry
        // the scope's ambient tenant/user state. The factory registration also registers KeywardDbContext
        // itself as a scoped service, so per-request consumers (API endpoints, startup seeding, tests) keep
        // injecting the context directly. Application services create a SHORT-LIVED context PER OPERATION
        // from the factory — in Blazor Server the DI scope is the whole circuit, and concurrent component
        // lifecycles sharing one scoped context raced ("a second operation was started on this context").
        services.AddDbContextFactory<KeywardDbContext>((sp, options) =>
            // EnableRetryOnFailure: without it EF uses the NON-retrying SqlServerExecutionStrategy, and a
            // seconds-long network blip (a SQL host's nightly maintenance window is the recurring one) fails
            // the operation outright — observed 13.08.2026 04:58 on svrsql05, «Physical connection is not
            // usable», straight out of this context. Consumers that open their own transaction must run it
            // inside Database.CreateExecutionStrategy().ExecuteAsync(...), which a retrying strategy requires.
            options.UseSqlServer(connectionString, sql =>
                    sql.EnableRetryOnFailure(maxRetryCount: 6, maxRetryDelay: TimeSpan.FromSeconds(30), errorNumbersToAdd: null)
                        .MigrationsHistoryTable("__EFMigrationsHistory", KeywardDbContext.Schema))
                .AddInterceptors(
                    sp.GetRequiredService<TenantSessionContextInterceptor>(),
                    sp.GetRequiredService<AuditChainInterceptor>(),
                    // Clear the change tracker after each save so a longer-lived scoped context does not
                    // accumulate tracked entities or serve stale reads (e.g. across a Blazor circuit).
                    sp.GetRequiredService<ChangeTrackerResetInterceptor>()),
            ServiceLifetime.Scoped);

        services.AddSingleton<IKekProvider>(kekProviderFactory);
        services.AddSingleton<IClock, SystemClock>();
        services.AddScoped<ISecretBackend, EnvelopeSecretBackend>();
        // The audit sink/directory are exposed twice: as their Core ports (scoped-context semantics — an
        // endpoint stages an entry and its own SaveChanges persists it) and as the concrete classes, whose
        // db-parametric overloads let a factory-based service stage the audit entry on ITS per-operation
        // context so audit and business write still commit in one SaveChanges.
        services.AddScoped<DbAuditSubjectDirectory>();
        services.AddScoped<IAuditSubjectDirectory>(sp => sp.GetRequiredService<DbAuditSubjectDirectory>());
        services.AddScoped<DbAuditSink>();
        services.AddScoped<IAuditSink>(sp => sp.GetRequiredService<DbAuditSink>());
        services.AddScoped<IAuditChainVerifier, DbAuditChainVerifier>();
        services.AddScoped<IKekIntegrityVerifier, DbKekIntegrityVerifier>();

        // Key OWNERSHIP: does the key this process holds actually open this database's data? Verified once
        // at host start against a known plaintext stored in the database (the canary), because no metadata
        // can answer it — the stored KekId names the key's format, and machine/path comparisons test a
        // recipe rather than the fact. The verdict gates the crypto path, so a mismatch stops at zero damage
        // instead of accumulating values the owning installation cannot read. Bind
        // KeywardKeyIntegrityOptions ("Keyward:KeyIntegrity") in the host to change what a conflict does.
        services.AddOptions<KeywardKeyIntegrityOptions>();
        services.AddSingleton<KeywardKeyIntegrityState>();
        services.AddScoped<KekCanaryService>();
        services.AddHostedService<KekIntegrityStartupCheck>();

        // The software-secrets service serves both the management path (by environment name) and the
        // software-client read path (by environment id); expose the one scoped instance via both ports.
        services.AddScoped<SoftwareSecretService>();
        services.AddScoped<ISoftwareSecretService>(sp => sp.GetRequiredService<SoftwareSecretService>());
        services.AddScoped<ISoftwareSecretReader>(sp => sp.GetRequiredService<SoftwareSecretService>());

        // Software projects ("Applications" in the UI): the unit bundling environments, secrets and tokens —
        // plus the tenant's default environment set every new application starts with.
        services.AddScoped<IProjectService, ProjectService>();
        services.AddScoped<IDefaultEnvironmentService, DefaultEnvironmentService>();
        // Bulk import of applications + secret keys (no values); composes the two services above.
        services.AddScoped<IApplicationImportService, ApplicationImportService>();

        // Software-client tokens: management + authentication, and a best-effort expiry watcher.
        services.AddScoped<ISoftwareClientTokenService, SoftwareClientTokenService>();
        services.AddScoped<ISoftwareClientAuthenticator, SoftwareClientAuthenticator>();
        services.AddHostedService<SoftwareClientTokenExpiryService>();

        // Token access statistics: in-memory recording on the hot path, batched persistence + rule-based
        // access-pattern alerts (new IP / resumed after silence) in the flush service, a read service for
        // the per-application statistics tab. Configure via the "Keyward:TokenAccess" section (optional).
        services.AddOptions<Statistics.TokenAccessOptions>().BindConfiguration(Statistics.TokenAccessOptions.SectionName);
        services.AddSingleton<Statistics.TokenAccessAccumulator>();
        services.AddSingleton<ITokenAccessRecorder>(sp => sp.GetRequiredService<Statistics.TokenAccessAccumulator>());
        services.AddScoped<ITokenAccessStatisticsService, Statistics.TokenAccessStatisticsService>();
        services.AddHostedService<Statistics.TokenAccessFlushService>();

        // Per-secret read statistics ("is this secret still used?"): recorded on every successful software
        // read (client API and in-process; management views don't count), upserted by the same flush
        // service — the "Keyward:TokenAccess" section's Enabled/FlushIntervalSeconds govern both.
        services.AddSingleton<Statistics.SecretReadAccumulator>();
        services.AddSingleton<ISecretReadRecorder>(sp => sp.GetRequiredService<Statistics.SecretReadAccumulator>());

        // Human vaults (server-side encrypted).
        services.AddScoped<IVaultService, VaultService>();

        // Break-glass: dual-control emergency access with an out-of-band, append-only non-repudiation sink.
        services.AddSingleton<IBreakGlassSink, FileBreakGlassSink>();
        services.AddScoped<IBreakGlassService, BreakGlassService>();

        // Ops monitoring: a periodic compliance/availability sweep (KEK integrity, audit-chain integrity,
        // token expiry) publishing a snapshot for the host's health endpoint to read cheaply.
        services.AddSingleton<Monitoring.OpsHealthSnapshot>();
        services.AddHostedService<Monitoring.OpsMonitorBackgroundService>();

        // Heartbeat monitoring (dead-man's switch): per-token silence monitors, evaluated periodically —
        // the access-pattern rules above fire when an access happens, a missing heartbeat needs a poller.
        // Configure via the "Keyward:Monitoring" section (optional; TimeZone is the installation's zone —
        // watch windows, statistics day buckets and mail timestamps; server-local when unset).
        services.AddOptions<Monitoring.MonitoringOptions>().BindConfiguration(Monitoring.MonitoringOptions.SectionName);
        services.AddScoped<ITokenAccessMonitorService, Monitoring.TokenAccessMonitorService>();
        services.AddHostedService<Monitoring.TokenAccessMonitorBackgroundService>();

        // Delivery of what the two rule sets above detect. It ships HERE, with detection, on purpose: while
        // this poller lived in the standalone shell an embedded Keyward recorded alerts and then dropped
        // them without a trace. Rendering and transport stay with the host behind IKeywardAlertPresenter —
        // register one, or this service says so loudly rather than discarding alerts.
        services.AddHostedService<Monitoring.TokenAccessAlertNotificationService>();
        services.AddHostedService<Monitoring.TokenExpiryNotificationService>();
        // Same schedule, other subject: software-secret values that carry a rotation date.
        services.AddHostedService<Monitoring.SecretExpiryNotificationService>();

        return services;
    }
}
