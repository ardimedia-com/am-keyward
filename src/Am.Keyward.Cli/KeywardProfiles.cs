using System.Text.Json;
using Am.Keyward.Client;

namespace Am.Keyward.Cli;

/// <summary>A named app token: which Keyward installation it belongs to. The token itself lives in the OS store.</summary>
internal sealed record KeywardProfile(string Name, Uri ServiceUri);

/// <summary>
/// The profiles of this OS user: their names and installations in a small JSON file (no secret in it), their tokens
/// in the Windows Credential Manager or the macOS Keychain under <c>AmKeyward:App:{profile}</c>. Where there is no such
/// store (Linux, a container) the token comes from <c>KEYWARD_PROFILE_{NAME}_TOKEN</c> and the installation from
/// <c>KEYWARD_PROFILE_{NAME}_SERVICE</c>.
/// </summary>
internal sealed class KeywardProfiles(string filePath, Func<string, IKeywardCredentialStore?> storeFor, Func<string, string?> environment)
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    /// <summary>The per-user default: <c>%APPDATA%\Keyward\profiles.json</c>, <c>~/.config/keyward/profiles.json</c> elsewhere.</summary>
    public static string DefaultFilePath =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            OperatingSystem.IsWindows() ? "Keyward" : "keyward",
            "profiles.json");

    public static KeywardProfiles ForThisUser() =>
        new(DefaultFilePath, KeywardCredentialStore.For, Environment.GetEnvironmentVariable);

    public IReadOnlyList<KeywardProfile> List() =>
        [.. Load().Select(p => new KeywardProfile(p.Key, new Uri(p.Value)))];

    public KeywardProfile Find(string name)
    {
        var key = Normalize(name);
        if (Load().TryGetValue(key, out var service))
        {
            return new KeywardProfile(key, new Uri(service));
        }

        if (environment(VariableFor(key, "SERVICE")) is { Length: > 0 } fromEnvironment
            && Uri.TryCreate(fromEnvironment, UriKind.Absolute, out var uri))
        {
            return new KeywardProfile(key, uri);
        }

        throw new KeywardCliException(KeywardExitCode.NoProfile,
            $"No profile '{key}' on this computer. Create it with: keyward login {key} --service https://keyward.example.com");
    }

    public string TokenFor(KeywardProfile profile)
    {
        if (storeFor(KeywardCredentialStore.AppProfileTarget(profile.Name))?.Read() is { Length: > 0 } stored)
        {
            return stored;
        }

        return environment(VariableFor(profile.Name, "TOKEN")) is { Length: > 0 } fromEnvironment
            ? fromEnvironment
            : throw new KeywardCliException(KeywardExitCode.NoProfile,
                $"No app token stored for profile '{profile.Name}'. Store it with: keyward login {profile.Name} --service {profile.ServiceUri.GetLeftPart(UriPartial.Authority)}");
    }

    /// <summary>Stores the token in the OS store and the profile in the file. Returns where the token went.</summary>
    public string Save(string name, Uri serviceUri, string token)
    {
        var key = Normalize(name);
        var store = storeFor(KeywardCredentialStore.AppProfileTarget(key))
            ?? throw new KeywardCliException(KeywardExitCode.Failed,
                $"There is no credential store here (Windows or macOS). Set {VariableFor(key, "TOKEN")} and {VariableFor(key, "SERVICE")} instead.");
        store.Write(token);

        var profiles = Load();
        profiles[key] = serviceUri.GetLeftPart(UriPartial.Authority);
        Write(profiles);
        return store.Place;
    }

    /// <summary>Forgets the profile and its token. False when there was neither.</summary>
    public bool Remove(string name)
    {
        var key = Normalize(name);
        var removedToken = storeFor(KeywardCredentialStore.AppProfileTarget(key))?.Delete() ?? false;
        var profiles = Load();
        var removedProfile = profiles.Remove(key);
        if (removedProfile)
        {
            Write(profiles);
        }

        return removedToken || removedProfile;
    }

    public bool HasStoredToken(KeywardProfile profile) =>
        storeFor(KeywardCredentialStore.AppProfileTarget(profile.Name))?.Read() is { Length: > 0 }
        || environment(VariableFor(profile.Name, "TOKEN")) is { Length: > 0 };

    internal static string VariableFor(string profile, string what) =>
        $"KEYWARD_PROFILE_{SecretReference.VariableNameFor(profile).ToUpperInvariant()}_{what}";

    private static string Normalize(string name)
    {
        var key = name.Trim().ToLowerInvariant();
        if (key.Length == 0 || key.Any(c => !(char.IsLetterOrDigit(c) || c is '-' or '_' or '.')))
        {
            throw new KeywardCliException(KeywardExitCode.Usage, $"'{name}' is no profile name - use letters, digits, '-', '_' or '.'.");
        }

        return key;
    }

    private Dictionary<string, string> Load()
    {
        if (!File.Exists(filePath))
        {
            return new Dictionary<string, string>(StringComparer.Ordinal);
        }

        var file = JsonSerializer.Deserialize<ProfilesFile>(File.ReadAllText(filePath), Json);
        return file?.Profiles is { } stored ? new Dictionary<string, string>(stored, StringComparer.Ordinal) : new Dictionary<string, string>(StringComparer.Ordinal);
    }

    private void Write(Dictionary<string, string> profiles)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(filePath)!);
        File.WriteAllText(filePath, JsonSerializer.Serialize(new ProfilesFile(new SortedDictionary<string, string>(profiles, StringComparer.Ordinal)), Json));
    }

    private sealed record ProfilesFile(IDictionary<string, string>? Profiles);
}
