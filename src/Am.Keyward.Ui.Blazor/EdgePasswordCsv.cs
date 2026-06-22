using Am.Keyward.Core.Application;

namespace Am.Keyward.Ui.Blazor;

/// <summary>
/// Parses a browser password-export CSV (Microsoft Edge / Google Chrome format, header columns
/// <c>name,url,username,password,note</c> — extra/missing columns and quoted fields are tolerated) into
/// <see cref="ImportedLogin"/> rows for the vault importer.
/// </summary>
public static class EdgePasswordCsv
{
    public static IReadOnlyList<ImportedLogin> Parse(string text)
    {
        var rows = ParseRows(text);
        if (rows.Count == 0)
        {
            return [];
        }

        var header = rows[0].Select(h => h.Trim().ToLowerInvariant()).ToList();
        var nameIdx = IndexOf(header, "name", "title");
        var urlIdx = IndexOf(header, "url", "website", "login_uri");
        var userIdx = IndexOf(header, "username", "login", "email", "login_username");
        var pwdIdx = IndexOf(header, "password", "login_password");
        var noteIdx = IndexOf(header, "note", "notes", "comment");

        var result = new List<ImportedLogin>();
        for (var r = 1; r < rows.Count; r++)
        {
            var cols = rows[r];
            var login = new ImportedLogin(Field(cols, nameIdx), Field(cols, urlIdx), Field(cols, userIdx), Field(cols, pwdIdx), Field(cols, noteIdx));
            if (!(string.IsNullOrWhiteSpace(login.Name) && string.IsNullOrWhiteSpace(login.Url) && string.IsNullOrWhiteSpace(login.Username)))
            {
                result.Add(login);
            }
        }

        return result;
    }

    private static int IndexOf(List<string> header, params string[] names) => header.FindIndex(names.Contains);

    private static string Field(string[] cols, int index) => index >= 0 && index < cols.Length ? cols[index] : "";

    /// <summary>Minimal RFC-4180 CSV reader: handles quoted fields, escaped quotes ("") and CRLF/LF.</summary>
    private static List<string[]> ParseRows(string text)
    {
        var rows = new List<string[]>();
        var fields = new List<string>();
        var field = new System.Text.StringBuilder();
        var inQuotes = false;

        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (inQuotes)
            {
                if (c == '"')
                {
                    if (i + 1 < text.Length && text[i + 1] == '"') { field.Append('"'); i++; }
                    else { inQuotes = false; }
                }
                else { field.Append(c); }
            }
            else if (c == '"') { inQuotes = true; }
            else if (c == ',') { fields.Add(field.ToString()); field.Clear(); }
            else if (c is '\r' or '\n')
            {
                if (c == '\r' && i + 1 < text.Length && text[i + 1] == '\n') { i++; }
                fields.Add(field.ToString());
                field.Clear();
                if (fields.Count > 1 || fields[0].Length > 0) { rows.Add([.. fields]); }
                fields.Clear();
            }
            else { field.Append(c); }
        }

        if (field.Length > 0 || fields.Count > 0)
        {
            fields.Add(field.ToString());
            if (fields.Count > 1 || fields[0].Length > 0) { rows.Add([.. fields]); }
        }

        return rows;
    }
}
