using System.Reflection;
using Am.Keyward.Infrastructure.Provisioning;
using Am.Keyward.Ui.Blazor.Provisioning;
using Microsoft.AspNetCore.Components;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Am.Keyward.Tests;

/// <summary>
/// The provisioning report has ONE hard requirement that is easy to break and impossible to notice in
/// development: it must render in a host where Keyward is switched OFF — no <c>AddKeyward</c>, no
/// <c>AddKeywardUi</c>, nothing but the diagnostics themselves. That is the entire point of the page it sits
/// on: an operator opens it precisely because Keyward is not running, and a page that throws there is worse
/// than no page, because the environment it was meant to explain is the one it fails in.
/// <para>
/// Blazor injects properties at render time, so a dependency the container cannot satisfy surfaces as a
/// runtime "Cannot provide a value for property …" — never as a build error. This guard asserts the contract
/// directly: every <see cref="InjectAttribute"/> the component carries must resolve from the minimal
/// container. A package-wide <c>@inject</c> in <c>_Imports.razor</c> (which applies to EVERY component in the
/// package) is exactly how that requirement gets broken by accident.
/// </para>
/// </summary>
[TestClass]
public sealed class ProvisioningReportRenderTests
{
    [TestMethod]
    [TestCategory("Unit")]
    public void EveryInjectedServiceResolvesInAHostWhereKeywardIsSwitchedOff()
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddLocalization();
        services.AddSingleton<IConfiguration>(new ConfigurationBuilder().Build());

        // Exactly what a host with Keyward disabled registers: the diagnostics, and nothing else.
        services.AddKeywardProvisioningStatus(
            new StubEnvironment(),
            o =>
            {
                o.Enabled = false;
                o.TenantId = Guid.Parse("b7d10000-0000-4000-8000-000000000001");
                o.TenantName = "Contoso";
            },
            addStartupCheck: false);

        using ServiceProvider provider = services.BuildServiceProvider();
        using IServiceScope scope = provider.CreateScope();

        PropertyInfo[] injected = [.. typeof(KeywardProvisioningReport)
            .GetProperties(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
            .Where(p => p.IsDefined(typeof(InjectAttribute), inherit: true))];

        Assert.IsTrue(injected.Length > 0, "The component should inject at least its status service.");

        List<string> unresolvable = [.. injected
            .Where(p => scope.ServiceProvider.GetService(p.PropertyType) is null)
            .Select(p => $"{p.Name} ({p.PropertyType.Name})")];

        Assert.AreEqual(
            0,
            unresolvable.Count,
            "The provisioning report must render where Keyward is switched off, but these injected services "
            + "are not registered there: " + string.Join(", ", unresolvable));
    }

    private sealed class StubEnvironment : IKeywardHostEnvironment
    {
        public string EnvironmentName => "Development";

        public bool IsDevelopment => true;
    }
}
