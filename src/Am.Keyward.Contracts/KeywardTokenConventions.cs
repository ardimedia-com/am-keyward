using System.Globalization;
using System.Text;

namespace Am.Keyward.Contracts;

/// <summary>
/// The convention connecting token issuance and token consumption: the environment-variable name a deployed
/// application reads its app token from. The server UI offers it in the deployment PowerShell snippet; the
/// client (<c>Am.Keyward.Client</c>) reads the same variable — one derivation, used by both sides.
/// </summary>
public static class KeywardTokenConventions
{
    /// <summary>
    /// Turns an application name into a conventional environment-variable name:
    /// <c>Bvd.Li.Toolbox</c> → <c>KEYWARD_BVD_LI_TOOLBOX_TOKEN</c>. Upper-case with underscores (not the
    /// hyphens of a slug) so it can be read as <c>$env:NAME</c> in PowerShell without bracing; diacritics
    /// are folded (<c>Bürosoftware</c> → <c>BUROSOFTWARE</c>) rather than replaced by underscores. The
    /// constant <c>KEYWARD_</c> prefix groups an installation's variables and keeps the name from starting
    /// with a digit.
    /// </summary>
    public static string DeriveTokenVariableName(string applicationName)
    {
        var folded = (applicationName ?? "").Normalize(NormalizationForm.FormD);
        var sb = new StringBuilder(folded.Length);
        foreach (var c in folded)
        {
            if (CharUnicodeInfo.GetUnicodeCategory(c) == UnicodeCategory.NonSpacingMark)
            {
                continue; // diacritic of the preceding base letter
            }

            var upper = char.ToUpperInvariant(c);
            var keep = upper is >= 'A' and <= 'Z' || upper is >= '0' and <= '9';
            if (keep)
            {
                sb.Append(upper);
            }
            else if (sb.Length > 0 && sb[^1] != '_')
            {
                sb.Append('_'); // one separator per run of punctuation/whitespace
            }
        }

        var core = sb.ToString().Trim('_');
        return core.Length == 0 ? "KEYWARD_APP_TOKEN" : $"KEYWARD_{core}_TOKEN";
    }
}
