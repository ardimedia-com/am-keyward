namespace Am.Keyward.Cli;

/// <summary>
/// Exit codes of `keyward` — one per cause, so a script fails with the reason rather than with the 401 of whatever it
/// called next (analysis §5.6). The message on stderr says the same in words.
/// </summary>
internal enum KeywardExitCode
{
    Ok = 0,

    /// <summary>Anything not covered below (server error, unexpected answer).</summary>
    Failed = 1,

    /// <summary>The command line is wrong.</summary>
    Usage = 2,

    /// <summary>No such profile, or no token stored for it.</summary>
    NoProfile = 3,

    /// <summary>The app token is unknown, revoked or expired (401).</summary>
    TokenRejected = 4,

    /// <summary>This computer's network may not use the API (403).</summary>
    NetworkNotAllowed = 5,

    /// <summary>The application has no such key.</summary>
    UnknownKey = 6,

    /// <summary>The key holds no value in the token's environment.</summary>
    NoValue = 7,

    /// <summary>Keyward did not answer in time or could not be reached.</summary>
    Unreachable = 8,
}

/// <summary>A failure that ends a command with its exit code and a one-line message.</summary>
internal sealed class KeywardCliException(KeywardExitCode code, string message) : Exception(message)
{
    public KeywardExitCode Code { get; } = code;
}
