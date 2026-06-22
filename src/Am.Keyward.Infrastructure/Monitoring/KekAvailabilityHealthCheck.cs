using System.Security.Cryptography;
using Am.Keyward.Core.Abstractions;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Am.Keyward.Infrastructure.Monitoring;

/// <summary>
/// Liveness of the key-encryption-key provider: wraps and unwraps a throwaway data key and confirms the
/// round-trip. If the KEK store (file/env/Key Vault/HSM) is unreachable or misconfigured, no secret can be
/// decrypted, so this reports Unhealthy. The probe DEK is random and zeroed; no real secret is touched.
/// </summary>
public sealed class KekAvailabilityHealthCheck(IKekProvider kek) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        var probe = RandomNumberGenerator.GetBytes(32);
        try
        {
            var wrapped = await kek.WrapAsync(probe, cancellationToken).ConfigureAwait(false);
            var unwrapped = await kek.UnwrapAsync(wrapped, kek.KekId, cancellationToken).ConfigureAwait(false);
            return CryptographicOperations.FixedTimeEquals(probe, unwrapped)
                ? HealthCheckResult.Healthy($"KEK '{kek.KekId}' wrap/unwrap round-trip succeeded.")
                : HealthCheckResult.Unhealthy("KEK round-trip did not recover the probe key.");
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy("KEK provider is unavailable.", ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(probe);
        }
    }
}
