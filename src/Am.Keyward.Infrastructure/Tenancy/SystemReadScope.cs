namespace Am.Keyward.Infrastructure.Tenancy;

/// <summary>
/// Scoped opt-in flag that grants the current DbContext connection a row-level-security READ bypass on the
/// audit and encrypted-version tables (never writes — the BLOCK predicates ignore it). It is translated to
/// <c>SESSION_CONTEXT('SystemBypass')</c> by <see cref="TenantSessionContextInterceptor"/> when a connection
/// opens. Set <see cref="Enabled"/> to <c>true</c> ONLY in trusted, tenant-less server-side maintenance
/// sweeps that must read across every tenant (the ops monitor's audit-chain discovery and the KEK-integrity
/// verifier). It defaults to <c>false</c>, so an ordinary request connection keeps full isolation.
/// </summary>
public sealed class SystemReadScope
{
    public bool Enabled { get; set; }
}
