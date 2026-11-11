using Microsoft.Extensions.Localization;

// The shell's own UI strings live in Resources/ShellResource*.resx. Declared on the assembly so the lookup does not
// depend on the LocalizationOptions.ResourcesPath (the RCL declares its own location the same way).
[assembly: ResourceLocation("Resources")]

namespace Am.Keyward.Ui.Blazor.App;

/// <summary>
/// Marker type for the reference shell's own UI strings (layout, account pages, invitation mail). Inject
/// <c>IStringLocalizer&lt;ShellResource&gt;</c>. The Keyward feature strings stay in the RCL's
/// <c>SharedResource</c>; this file holds only what the shell itself renders.
/// </summary>
public sealed class ShellResource;
