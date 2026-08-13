using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Infrastructure.Provisioning;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Am.Keyward.Infrastructure.Software;

/// <summary>Which Keyward application ("project") a host reads its OWN machine credentials from.</summary>
public sealed class KeywardMachineSecretsOptions
{
    /// <summary>
    /// The application name. By convention the deployed host's entry-assembly name — one Keyward application
    /// per deployed piece of software, matching how the org identifies software elsewhere (log paths, mail
    /// senders, token environment variables).
    /// </summary>
    public string ApplicationName { get; set; } = string.Empty;
}

/// <summary>
/// In-process reader for a HOST'S OWN machine credentials — the secrets of its
/// <see cref="KeywardMachineSecretsOptions.ApplicationName"/> application, keyed by the runtime environment
/// (Development / Test / Preview / Production, which match Keyward's default environment set).
///
/// <para>Read a secret by key with <see cref="ReadAsync"/>; a <c>null</c> result means "not stored in
/// Keyward", so the caller falls back to its existing configuration or environment variable — KEYWARD-FIRST
/// WITH CONFIG FALLBACK. That fallback is what lets a host adopt Keyward for its credentials one key at a
/// time, and keeps it running when Keyward is unavailable.</para>
///
/// <para>This is the IN-PROCESS counterpart of <c>Am.Keyward.Client</c>: a host that embeds Keyward reads its
/// own secrets straight from the services, without a token or an HTTP hop.</para>
/// </summary>
public sealed class KeywardMachineSecrets(
    ISoftwareSecretService secrets,
    IProjectService projects,
    IKeywardWorkspaceContext workspace,
    ITenantScopeSetter tenantScope,
    IOptions<KeywardMachineSecretsOptions> options,
    IKeywardHostEnvironment environment,
    ILogger<KeywardMachineSecrets> logger)
{
    #region Properties

    /// <summary>The application whose secrets are read.</summary>
    public string ApplicationName => options.Value.ApplicationName;

    /// <summary>The runtime environment the secrets are read for.</summary>
    public string EnvironmentName => environment.EnvironmentName;

    #endregion

    #region Public Methods

    /// <summary>
    /// Reads one machine secret for the current runtime environment, or <c>null</c> when it is not stored in
    /// Keyward (the caller then falls back to its configured value). Never throws — a Keyward hiccup degrades
    /// to <c>null</c> so the caller's fallback keeps the application working.
    /// </summary>
    public async Task<string?> ReadAsync(string key, CancellationToken cancellationToken = default)
    {
        try
        {
            Guid tenantId = workspace.TenantId;
            tenantScope.SetTenant(tenantId);   // software secrets are tenant-scoped (row-level security)

            if (await this.ResolveProjectIdAsync(tenantId, cancellationToken).ConfigureAwait(false) is not { } projectId)
            {
                return null;
            }

            return await secrets.ReadAsync(
                new ReadSoftwareSecretQuery(tenantId, projectId, this.EnvironmentName, key, ActorUserId: null),
                cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            logger.LogDebug(ex, "KEYWARD: reading machine secret '{Key}' failed; the caller falls back to configuration.", key);
            return null;
        }
    }

    /// <summary>The id of the host's own application, or <c>null</c> when it has not been seeded yet.</summary>
    public async Task<Guid?> ResolveProjectIdAsync(CancellationToken cancellationToken = default)
    {
        tenantScope.SetTenant(workspace.TenantId);
        return await this.ResolveProjectIdAsync(workspace.TenantId, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Reads EVERY secret of the host's application that has a value in the current runtime environment — the
    /// startup "keyward-first" configuration overlay. Deliberately read key-by-key through the in-process
    /// path (not a bulk reader), so the per-secret read statistics attribute these reads as in-process rather
    /// than as a client-token read. Never throws — a Keyward hiccup returns an empty result and the
    /// configuration values stay in effect.
    /// </summary>
    public async Task<IReadOnlyDictionary<string, string>> ReadAllAsync(CancellationToken cancellationToken = default)
    {
        Dictionary<string, string> result = [];
        try
        {
            Guid tenantId = workspace.TenantId;
            tenantScope.SetTenant(tenantId);

            if (await this.ResolveProjectIdAsync(tenantId, cancellationToken).ConfigureAwait(false) is not { } projectId)
            {
                return result;
            }

            IReadOnlyList<SoftwareSecretSummary> keys =
                await secrets.ListSecretsAsync(tenantId, projectId, cancellationToken).ConfigureAwait(false);

            foreach (SoftwareSecretSummary key in keys)
            {
                string? value = await secrets.ReadAsync(
                    new ReadSoftwareSecretQuery(tenantId, projectId, this.EnvironmentName, key.Key, ActorUserId: null),
                    cancellationToken).ConfigureAwait(false);
                if (value is not null)
                {
                    result[key.Key] = value;
                }
            }
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "KEYWARD: reading the machine-secret overlay failed; configuration values remain in effect.");
        }

        return result;
    }

    #endregion

    #region Private Methods

    private async Task<Guid?> ResolveProjectIdAsync(Guid tenantId, CancellationToken cancellationToken)
    {
        IReadOnlyList<ProjectInfo> all = await projects.ListAsync(tenantId, cancellationToken).ConfigureAwait(false);
        return all.FirstOrDefault(p => string.Equals(p.Name, this.ApplicationName, StringComparison.Ordinal))?.Id;
    }

    #endregion
}
