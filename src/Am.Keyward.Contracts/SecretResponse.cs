namespace Am.Keyward.Contracts;

/// <summary>Wire shape of a single-secret read (<c>GET .../secrets/{key}</c>).</summary>
public sealed record SecretResponse(string Key, string Value);
