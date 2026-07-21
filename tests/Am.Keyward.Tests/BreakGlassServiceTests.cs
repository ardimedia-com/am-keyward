using System.Security.Cryptography;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Domain;
using Am.Keyward.Core.Domain.Identity;
using Am.Keyward.Core.Domain.ValueObjects;
using Am.Keyward.Infrastructure;
using Am.Keyward.Infrastructure.Auth;
using Am.Keyward.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Am.Keyward.Tests;

/// <summary>
/// Break-glass end-to-end: only a System Admin may request, no self-approval (dual control), an approval by
/// a second admin is written to the out-of-band sink and the audit chain, and the grant is then consumable.
/// Runs against a real SQL Server; skips when none is reachable.
/// </summary>
[TestClass]
public class BreakGlassServiceTests
{
    private static readonly string ConnectionString = TestConfig.ConnectionString;

    [TestMethod, TestCategory("Integration")]
    public async Task Dual_control_request_approve_consume_with_non_repudiable_sink()
    {
        var tenantId = Guid.NewGuid();
        var requester = Guid.NewGuid();
        var approver = Guid.NewGuid();
        var outsider = Guid.NewGuid();
        var sinkPath = Path.Combine(Path.GetTempPath(), $"bg-{Path.GetRandomFileName()}.jsonl");

        var services = new ServiceCollection();
        services.AddKeyward(ConnectionString, RandomNumberGenerator.GetBytes(32), "test-kek:v1");
        services.Configure<BreakGlassOptions>(o => o.SinkFilePath = sinkPath);
        await using var provider = services.BuildServiceProvider();

        try
        {
            using (var scope = ScopeFor(provider, tenantId))
            {
                var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
                if (!await db.Database.CanConnectAsync())
                {
                    Assert.Inconclusive("SQL Server not reachable — skipping integration test.");
                    return;
                }

                db.Users.Add(new AppUser(requester, null, requester.ToString("D"), "Admin One", isSystemAdmin: true, DateTimeOffset.UtcNow));
                db.Users.Add(new AppUser(approver, null, approver.ToString("D"), "Admin Two", isSystemAdmin: true, DateTimeOffset.UtcNow));
                db.Users.Add(new AppUser(outsider, null, outsider.ToString("D"), "Regular", isSystemAdmin: false, DateTimeOffset.UtcNow));
                await db.SaveChangesAsync();
            }

            var scopeTarget = new GrantScope(GrantScopeKind.Vault, Guid.NewGuid());

            // A non-admin cannot even request.
            using (var scope = ScopeFor(provider, tenantId))
            {
                var svc = scope.ServiceProvider.GetRequiredService<IBreakGlassService>();
                await Assert.ThrowsExactlyAsync<UnauthorizedAccessException>(
                    () => svc.RequestAsync(new RequestBreakGlassCommand(tenantId, scopeTarget, outsider, "should fail")));
            }

            Guid grantId;
            using (var scope = ScopeFor(provider, tenantId))
            {
                var svc = scope.ServiceProvider.GetRequiredService<IBreakGlassService>();
                grantId = await svc.RequestAsync(new RequestBreakGlassCommand(tenantId, scopeTarget, requester, "incident-42 recovery"));
            }

            // The requester cannot approve their own request (dual control).
            using (var scope = ScopeFor(provider, tenantId))
            {
                var svc = scope.ServiceProvider.GetRequiredService<IBreakGlassService>();
                await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => svc.ApproveAsync(grantId, requester));
            }

            // A second admin approves.
            using (var scope = ScopeFor(provider, tenantId))
            {
                await scope.ServiceProvider.GetRequiredService<IBreakGlassService>().ApproveAsync(grantId, approver);
            }

            // The approval is recorded out-of-band (non-repudiation) and in the audit chain.
            var sinkText = await File.ReadAllTextAsync(sinkPath);
            StringAssert.Contains(sinkText, "Approved");

            using (var scope = ScopeFor(provider, tenantId))
            {
                var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
                var breakGlassAudits = await db.AuditEntries.CountAsync(a => a.TenantId == tenantId && a.Action == AuditAction.BreakGlass);
                Assert.IsGreaterThanOrEqualTo(2, breakGlassAudits, "Request and approve should both be audited.");

                var status = await scope.ServiceProvider.GetRequiredService<IAuditChainVerifier>().VerifyAsync(tenantId);
                Assert.IsTrue(status.IsIntact, status.Detail);
            }

            // The approved grant can be consumed once.
            using (var scope = ScopeFor(provider, tenantId))
            {
                await scope.ServiceProvider.GetRequiredService<IBreakGlassService>().ConsumeAsync(grantId, approver);
            }

            using (var scope = ScopeFor(provider, tenantId))
            {
                var grant = await scope.ServiceProvider.GetRequiredService<KeywardDbContext>()
                    .BreakGlassGrants.FirstAsync(g => g.Id == grantId);
                Assert.AreEqual(BreakGlassStatus.Consumed, grant.Status);
            }

            // Consumption materialized the emergency access as a REGULAR Manage grant for the REQUESTER
            // (not the consuming approver) — visible in the normal ACL and revocable after the recovery.
            using (var scope = ScopeFor(provider, tenantId))
            {
                var db = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
                var materialized = await db.AccessGrants.SingleAsync(g =>
                    g.PrincipalType == PrincipalType.User
                    && g.PrincipalId == requester
                    && g.Scope.Kind == scopeTarget.Kind
                    && g.Scope.TargetId == scopeTarget.TargetId);
                Assert.AreEqual(Permission.Manage, materialized.Permission);
                Assert.AreEqual(tenantId, materialized.TenantId);
            }
        }
        finally
        {
            if (File.Exists(sinkPath))
            {
                File.Delete(sinkPath);
            }
        }
    }

    private static IServiceScope ScopeFor(ServiceProvider provider, Guid tenantId)
    {
        var scope = provider.CreateScope();
        scope.ServiceProvider.GetRequiredService<ITenantScopeSetter>().SetTenant(tenantId);
        return scope;
    }
}
