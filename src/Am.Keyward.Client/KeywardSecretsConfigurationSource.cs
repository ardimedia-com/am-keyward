using Microsoft.Extensions.Configuration;

namespace Am.Keyward.Client;

/// <summary>Configuration source for Keyward-hosted application secrets (see <c>AddKeywardSecrets</c>).</summary>
public sealed class KeywardSecretsConfigurationSource(KeywardSecretsOptions options) : IConfigurationSource
{
    public KeywardSecretsOptions Options { get; } = options;

    public IConfigurationProvider Build(IConfigurationBuilder builder) =>
        new KeywardSecretsConfigurationProvider(Options);
}
