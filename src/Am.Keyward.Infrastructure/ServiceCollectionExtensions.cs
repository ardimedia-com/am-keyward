using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Infrastructure.Crypto;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Am.Keyward.Infrastructure;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers AM KEYWARD against a SQL Server database and an in-memory KEK (file/env-loaded by the
    /// host). The migrations-history table is scoped to the <c>amkeyward</c> schema so it never collides
    /// with the host's migrations.
    /// </summary>
    public static IServiceCollection AddKeyward(this IServiceCollection services, string connectionString, byte[] kek, string kekId)
    {
        services.AddDbContext<KeywardDbContext>(options =>
            options.UseSqlServer(connectionString, sql =>
                sql.MigrationsHistoryTable("__EFMigrationsHistory", KeywardDbContext.Schema)));

        services.AddSingleton<IKekProvider>(new StaticKekProvider(kek, kekId));
        services.AddSingleton<IClock, SystemClock>();
        services.AddScoped<ISecretBackend, EnvelopeSecretBackend>();
        services.AddScoped<IAuditSink, DbAuditSink>();
        services.AddScoped<ISoftwareSecretService, SoftwareSecretService>();

        return services;
    }
}
