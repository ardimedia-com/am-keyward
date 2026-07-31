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
            options.UseSqlServer(connectionString, sql =>
                    sql.MigrationsHistoryTable("__EFMigrationsHistory", KeywardDbContext.Schema))
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

        // The software-secrets service serves both the management path (by environment name) and the
        // software-client read path (by environment id); expose the one scoped instance via both ports.
        services.AddScoped<SoftwareSecretService>();
        services.AddScoped<ISoftwareSecretService>(sp => sp.GetRequiredService<SoftwareSecretService>());
        services.AddScoped<ISoftwareSecretReader>(sp => sp.GetRequiredService<SoftwareSecretService>());

        // Software projects ("Applications" in the UI): the unit bundling environments, secrets and tokens —
        // plus the tenant's default environment set every new application starts with.
        services.AddScoped<IProjectService, ProjectService>();
        services.AddScoped<IDefaultEnvironmentService, DefaultEnvironmentService>();

        // Software-client tokens: management + authentication, and a best-effort expiry watcher.
        services.AddScoped<ISoftwareClientTokenService, SoftwareClientTokenService>();
        services.AddScoped<ISoftwareClientAuthenticator, SoftwareClientAuthenticator>();
        services.AddHostedService<SoftwareClientTokenExpiryService>();

        // Token access statistics: in-memory recording on the hot path, batched persistence + rule-based
        // access-pattern alerts (new IP / resumed after silence) in the flush service, a read service for
        // the per-application statistics tab. Configure via the "Keyward:TokenAccess" section (optional).
        services.AddOptions<Statistics.TokenAccessOptions>();
        services.AddSingleton<Statistics.TokenAccessAccumulator>();
        services.AddSingleton<ITokenAccessRecorder>(sp => sp.GetRequiredService<Statistics.TokenAccessAccumulator>());
        services.AddScoped<ITokenAccessStatisticsService, Statistics.TokenAccessStatisticsService>();
        services.AddHostedService<Statistics.TokenAccessFlushService>();

        // Human vaults (server-side encrypted).
        services.AddScoped<IVaultService, VaultService>();

        // Break-glass: dual-control emergency access with an out-of-band, append-only non-repudiation sink.
        services.AddSingleton<IBreakGlassSink, FileBreakGlassSink>();
        services.AddScoped<IBreakGlassService, BreakGlassService>();

        // Ops monitoring: a periodic compliance/availability sweep (KEK integrity, audit-chain integrity,
        // token expiry) publishing a snapshot for the host's health endpoint to read cheaply.
        services.AddSingleton<Monitoring.OpsHealthSnapshot>();
        services.AddHostedService<Monitoring.OpsMonitorBackgroundService>();

        return services;
    }
}
