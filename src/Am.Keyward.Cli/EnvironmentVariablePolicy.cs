using System.Text.RegularExpressions;

namespace Am.Keyward.Cli;

/// <summary>
/// Which environment-variable names `keyward run` and `keyward env` may set. A name made from a key (<c>--all</c>,
/// <c>env</c>) is chosen by whoever can create keys in the application — a person with access, or an agent with
/// «Manage applications» — not by the person running the command. Such a name must therefore not be one that changes
/// how the started program or the shell itself behaves: the loader, interpreter and shell variables below (<c>PATH</c>,
/// <c>LD_PRELOAD</c>, <c>DOTNET_STARTUP_HOOKS</c>, <c>NODE_OPTIONS</c>, …) are refused unless the caller lists the name
/// with <c>--allow-name</c>. Every name must also be portable: a letter or <c>_</c>, then letters, digits or <c>_</c>.
/// </summary>
internal static partial class EnvironmentVariablePolicy
{
    // Exact names (compared case-insensitively — Windows treats variable names that way).
    private static readonly HashSet<string> ProtectedNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "PATH", "PATHEXT", "COMSPEC", "SHELL", "HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA",
        "PROGRAMDATA", "TEMP", "TMP", "TMPDIR", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR",
        "BASH_ENV", "ENV", "PROMPT_COMMAND", "PROMPT", "PS1", "PS2", "PS3", "PS4", "IFS", "CDPATH", "ZDOTDIR",
        "PSMODULEPATH", "PSEXECUTIONPOLICYPREFERENCE",
        "NODE_OPTIONS", "NODE_PATH", "RUBYOPT", "RUBYLIB", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS",
        "CLASSPATH", "PERLLIB", "LUA_INIT", "TCLLIBPATH",
        "GIT_SSH", "GIT_SSH_COMMAND", "GIT_EXEC_PATH", "GIT_ASKPASS", "GIT_PROXY_COMMAND", "GIT_CONFIG_COUNT",
        "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "SSH_ASKPASS", "EDITOR", "VISUAL", "PAGER",
    };

    // Prefixes of families that load code or redirect a runtime (case-insensitive).
    private static readonly string[] ProtectedPrefixes =
    [
        "LD_", "DYLD_", "DOTNET_", "COR_", "CORECLR_", "COMPLUS_", "PYTHON", "PERL5", "NPM_CONFIG_", "GIT_CONFIG_KEY_",
        "GIT_CONFIG_VALUE_",
    ];

    [GeneratedRegex("^[A-Za-z_][A-Za-z0-9_]*$", RegexOptions.CultureInvariant)]
    private static partial Regex PortableName();

    public static bool IsPortable(string name) => PortableName().IsMatch(name);

    public static bool IsProtected(string name) =>
        ProtectedNames.Contains(name) || ProtectedPrefixes.Any(p => name.StartsWith(p, StringComparison.OrdinalIgnoreCase));

    /// <summary>A name the caller typed (<c>--env NAME=…</c>): it must be portable; the caller chose it, so it may be any.</summary>
    public static void CheckChosen(string name)
    {
        if (!IsPortable(name))
        {
            throw new KeywardCliException(KeywardExitCode.Usage,
                $"'{name}' is no portable environment-variable name - use a letter or '_', then letters, digits or '_'.");
        }
    }

    /// <summary>A name made from a key: portable, and not a protected variable unless <paramref name="allowed"/> lists it.</summary>
    public static void CheckFromKey(string name, string key, IReadOnlySet<string> allowed)
    {
        if (!IsPortable(name))
        {
            throw new KeywardCliException(KeywardExitCode.Usage,
                $"Key '{key}' would become '{name}', which is no portable environment-variable name. Use --prefix (e.g. --prefix APP_), or pass it with --env NAME=<profile>:<key>.");
        }

        if (IsProtected(name) && !allowed.Contains(name))
        {
            throw new KeywardCliException(KeywardExitCode.Usage,
                $"Key '{key}' would set '{name}', which changes how programs or the shell start (loader, interpreter or shell variable). Nothing was set. "
                + $"Use --prefix (e.g. --prefix APP_), or allow it explicitly with --allow-name {name} if that key is meant to set it.");
        }
    }
}
