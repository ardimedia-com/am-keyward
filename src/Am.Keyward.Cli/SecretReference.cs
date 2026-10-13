namespace Am.Keyward.Cli;

/// <summary>
/// <c>profile:key</c> — which stored app token to use and which key to read with it. The token fixes application and
/// environment, so nothing else is needed. Keys may contain colons themselves (<c>ops:Prtg:ApiToken</c> reads key
/// <c>Prtg:ApiToken</c> with profile <c>ops</c>): the profile ends at the first colon.
/// </summary>
internal readonly record struct SecretReference(string Profile, string Key)
{
    public static SecretReference Parse(string text)
    {
        var colon = text.IndexOf(':');
        if (colon <= 0 || colon == text.Length - 1)
        {
            throw new KeywardCliException(KeywardExitCode.Usage, $"'{text}' is not a reference - write profile:key, e.g. ops:Prtg:ApiToken.");
        }

        return new SecretReference(text[..colon].Trim(), text[(colon + 1)..].Trim());
    }

    public override string ToString() => $"{Profile}:{Key}";

    /// <summary>
    /// The environment-variable name for a key, as .NET configuration reads it (<c>Prtg:ApiToken</c> →
    /// <c>Prtg__ApiToken</c>), with an optional prefix; characters a variable name cannot hold become «_».
    /// </summary>
    public static string VariableNameFor(string key, string prefix = "")
    {
        var name = prefix + key.Replace(":", "__", StringComparison.Ordinal);
        return new string([.. name.Select(c => char.IsLetterOrDigit(c) || c == '_' ? c : '_')]);
    }
}
