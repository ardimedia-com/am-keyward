using Am.Keyward.Ui.Blazor;

namespace Am.Keyward.Tests;

/// <summary>
/// The env-variable name offered in the app-token PowerShell snippet: derived per application by default
/// (so two applications on one host cannot collide), overridden by the host only when it configures a
/// fixed name.
/// </summary>
[TestClass]
public class TokenEnvironmentVariableNameTests
{
    [TestMethod, TestCategory("Unit")]
    [DataRow("Bvd.Li.Toolbox", "KEYWARD_BVD_LI_TOOLBOX_TOKEN")]
    [DataRow("orders service", "KEYWARD_ORDERS_SERVICE_TOKEN")]
    [DataRow("  Weelinq.com  ", "KEYWARD_WEELINQ_COM_TOKEN")]
    [DataRow("Shop -- 2026", "KEYWARD_SHOP_2026_TOKEN")]      // runs of punctuation collapse to one '_'
    [DataRow("Bürosoftware", "KEYWARD_BUROSOFTWARE_TOKEN")]   // diacritics fold, they do not become '_'
    [DataRow("3M Portal", "KEYWARD_3M_PORTAL_TOKEN")]         // the prefix keeps it from starting with a digit
    [DataRow("...", "KEYWARD_APP_TOKEN")]                     // nothing usable left
    [DataRow("", "KEYWARD_APP_TOKEN")]
    public void Derives_a_conventional_variable_name(string applicationName, string expected) =>
        Assert.AreEqual(expected, KeywardUiOptions.DeriveTokenVariableName(applicationName));

    [TestMethod, TestCategory("Unit")]
    public void A_host_configured_fixed_name_wins_over_the_derived_one()
    {
        var options = new KeywardUiOptions { TokenEnvironmentVariableName = "CONTOSO_SECRETS_TOKEN" };
        Assert.AreEqual("CONTOSO_SECRETS_TOKEN", options.TokenVariableFor("Bvd.Li.Toolbox"));
    }

    [TestMethod, TestCategory("Unit")]
    public void Unset_falls_back_to_the_per_application_name() =>
        Assert.AreEqual("KEYWARD_BVD_LI_TOOLBOX_TOKEN", new KeywardUiOptions().TokenVariableFor("Bvd.Li.Toolbox"));
}
