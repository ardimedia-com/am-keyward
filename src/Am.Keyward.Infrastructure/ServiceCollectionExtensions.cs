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

        services.AddScoped<IAuthorizationService, TenantAuthorizationService>();
        services.AddScoped<ITenantMembership, TenantMembershipService>();
        services.AddScoped<SystemReadScope>();
        services.AddScoped<TenantSessionContextInterceptor>();
        services.AddScoped<AuditChainInterceptor>();

        services.AddDbContext<KeywardDbContext>((sp, options) =>
            options.UseSqlServer(connectionString, sql =>
                    sql.MigrationsHistoryTable("__EFMigrationsHistory", KeywardDbContext.Schema))
                .AddInterceptors(
                    sp.GetRequiredService<TenantSessionContextInterceptor>(),
                    sp.GetRequiredService<AuditChainInterceptor>()));

        services.AddSingleton<IKekProvider>(kekProviderFactory);
        services.AddSingleton<IClock, SystemClock>();
        services.AddScoped<ISecretBackend, EnvelopeSecretBackend>();
        services.AddScoped<IAuditSubjectDirectory, DbAuditSubjectDirectory>();
        services.AddScoped<IAuditSink, DbAuditSink>();
        services.AddScoped<IAuditChainVerifier, DbAuditChainVerifier>();
        services.AddScoped<IKekIntegrityVerifier, DbKekIntegrityVerifier>();

        // The software-secrets service serves both the management path (by environment name) and the
        // software-client read path (by environment id); expose the one scoped instance via both ports.
        services.AddScoped<SoftwareSecretService>();
        services.AddScoped<ISoftwareSecretService>(sp => sp.GetRequiredService<SoftwareSecretService>());
        services.AddScoped<ISoftwareSecretReader>(sp => sp.GetRequiredService<SoftwareSecretService>());

        // Software-client tokens: management + authentication, and a best-effort expiry watcher.
        services.AddScoped<ISoftwareClientTokenService, SoftwareClientTokenService>();
        services.AddScoped<ISoftwareClientAuthenticator, SoftwareClientAuthenticator>();
        services.AddHostedService<SoftwareClientTokenExpiryService>();

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
