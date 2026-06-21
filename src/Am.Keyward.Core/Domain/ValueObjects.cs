using System.Text.RegularExpressions;

namespace Am.Keyward.Core.Domain.ValueObjects;

/// <summary>
/// Immutable encrypted-secret envelope. It carries ciphertext and the metadata needed to decrypt it,
/// but no plaintext and no decrypt behaviour — the bytes are only meaningful together. The AAD that
/// binds this envelope to its logical slot (tenant/owner/project/environment/item/version) is computed
/// by the infrastructure crypto layer; <see cref="FormatVersion"/> and <see cref="AlgVersion"/> allow
/// format/algorithm agility.
/// </summary>
public sealed record EncryptedValue(
    byte[] Ciphertext,
    byte[] Nonce,
    byte[] AuthTag,
    byte[] WrappedDek,
    string KekId,
    string WrapAlg,
    int AlgVersion,
    int FormatVersion);

/// <summary>
/// A software-secret key, validated to be a configuration-style key (e.g. <c>Shopify:AccessToken</c>,
/// <c>ConnectionStrings:Main</c>) so it maps cleanly onto <c>IConfiguration</c> (<c>Section:Key</c>).
/// </summary>
public sealed partial record SecretKey
{
    public string Value { get; }

    private SecretKey(string value) => Value = value;

    public static SecretKey Create(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("Secret key must not be empty.", nameof(value));
        }

        var trimmed = value.Trim();
        if (!KeyPattern().IsMatch(trimmed))
        {
            throw new ArgumentException(
                $"Secret key '{value}' is not a valid configuration key (expected ':'-separated segments like 'Section:Key').",
                nameof(value));
        }

        return new SecretKey(trimmed);
    }

    public override string ToString() => Value;

    // One or more ':'-separated segments; each segment uses letters/digits/_/-/. and is non-empty.
    [GeneratedRegex(@"^[A-Za-z0-9_.\-]+(:[A-Za-z0-9_.\-]+)*$")]
    private static partial Regex KeyPattern();
}

/// <summary>A runtime-environment name (e.g. Development/Test/Preview/Production); unique per project.</summary>
public sealed record EnvironmentName
{
    public string Value { get; }

    private EnvironmentName(string value) => Value = value;

    public static EnvironmentName Create(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("Environment name must not be empty.", nameof(value));
        }

        return new EnvironmentName(value.Trim());
    }

    public override string ToString() => Value;

    public static EnvironmentName Development { get; } = new("Development");
    public static EnvironmentName Test { get; } = new("Test");
    public static EnvironmentName Preview { get; } = new("Preview");
    public static EnvironmentName Production { get; } = new("Production");

    /// <summary>The default environment set a new project starts with; customizable per project.</summary>
    public static IReadOnlyList<EnvironmentName> DefaultSet { get; } =
        [Development, Test, Preview, Production];
}

/// <summary>What an <see cref="Access.AccessGrant"/> targets: a whole vault, a project, or one environment.</summary>
public sealed record GrantScope(GrantScopeKind Kind, Guid TargetId);
