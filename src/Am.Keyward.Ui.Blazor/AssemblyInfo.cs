using Microsoft.Extensions.Localization;

// The UI strings live in Resources/SharedResource*.resx. Declaring the location ON this assembly makes the
// localizer find them regardless of the HOST's LocalizationOptions.ResourcesPath — an embedding host must
// not have to configure its own resource path around ours.
[assembly: ResourceLocation("Resources")]
