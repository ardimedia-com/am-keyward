namespace Am.Keyward.Client;

/// <summary>What <see cref="KeywardSecretsClient.LookupAsync"/> found.</summary>
public enum KeywardSecretLookupStatus
{
    Found,

    /// <summary>The application has no key of that name.</summary>
    UnknownKey,

    /// <summary>The key exists but holds no value in the token's environment.</summary>
    NoValue,

    /// <summary>The token is unknown, revoked or expired (401).</summary>
    TokenRejected,

    /// <summary>The caller's network may not use the software-client API (403).</summary>
    NetworkNotAllowed,
}

/// <summary>A single-key lookup: the value when <see cref="Status"/> is <see cref="KeywardSecretLookupStatus.Found"/>.</summary>
public sealed record KeywardSecretLookup(KeywardSecretLookupStatus Status, string? Value);
