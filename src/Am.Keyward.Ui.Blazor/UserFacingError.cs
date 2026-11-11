using System.Diagnostics;
using Am.Keyward.Core.Application;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging;

namespace Am.Keyward.Ui.Blazor;

/// <summary>
/// Turns an exception from a UI action into the text the user sees. Only Keyward's own domain messages are shown
/// as they are — a validation or permission refusal thrown by Keyward code, or a version conflict (localized). Any
/// other exception (database, framework, a bug) may carry internals — a SQL error, a file path, a type name — so it
/// is logged and the user gets a generic, localized message instead.
/// </summary>
internal static class UserFacingError
{
    /// <summary>The text for <paramref name="exception"/>; unexpected exceptions are logged here.</summary>
    public static string Describe(Exception exception, IStringLocalizer localizer, ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(exception);
        ArgumentNullException.ThrowIfNull(localizer);
        ArgumentNullException.ThrowIfNull(logger);

        if (IsConcurrencyConflict(exception))
        {
            return localizer["Common.Error.Conflict"];
        }

        if (IsDomainMessage(exception))
        {
            return localizer["Common.Error"] + exception.Message;
        }

        logger.LogError(exception, "A Keyward UI action failed unexpectedly");
        return localizer["Common.Error.Unexpected"];
    }

    /// <summary>Someone changed the record since it was read: Keyward's own conflict types or EF's (matched by name,
    /// the RCL does not reference EF).</summary>
    internal static bool IsConcurrencyConflict(Exception exception) =>
        exception is VaultItemVersionConflictException or SecretValueVersionConflictException
        || exception.GetType().Name == "DbUpdateConcurrencyException";

    /// <summary>
    /// A message written for people: Keyward's own exception types, or one of the BCL types the services use for
    /// validation and refusals (argument, invalid operation, unauthorized, not found) — but only when Keyward code threw
    /// it. The same types thrown inside EF Core, SqlClient or the BCL carry technical text and are not shown.
    /// </summary>
    internal static bool IsDomainMessage(Exception exception) => exception switch
    {
        AgentApplicationsNotPermittedException or AgentApplicationNotFoundException
            or AgentApplicationConflictException or AgentApplicationChangeRefusedException => true,
        ArgumentException or InvalidOperationException or UnauthorizedAccessException or KeyNotFoundException
            => ThrownByKeyward(exception),
        _ => false,
    };

    /// <summary>
    /// True when the innermost frame that is not a throw helper (<c>ArgumentException.ThrowIfNullOrEmpty</c>,
    /// <c>ThrowHelper</c>) belongs to a Keyward assembly.
    /// </summary>
    internal static bool ThrownByKeyward(Exception exception)
    {
        foreach (var frame in new StackTrace(exception, fNeedFileInfo: false).GetFrames())
        {
            var type = frame.GetMethod()?.DeclaringType;
            if (type is null)
            {
                continue;
            }

            if (typeof(Exception).IsAssignableFrom(type) || type.Name == "ThrowHelper")
            {
                continue;
            }

            return type.Assembly.GetName().Name?.StartsWith("Am.Keyward.", StringComparison.Ordinal) == true;
        }

        return false;
    }
}
