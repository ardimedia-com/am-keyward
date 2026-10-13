namespace Am.Keyward.Client;

/// <summary>
/// Entering a token at a console (`amkeyward-mcp setup`, `keyward login`): the characters are never echoed, one «*»
/// per character shows that a paste arrived, and <see cref="Mask"/> confirms what was received without the secret.
/// </summary>
public static class KeywardTokenInput
{
    /// <summary>Reads a line from the console without echoing it; «*» per character, Backspace works.</summary>
    public static string ReadHidden()
    {
        var chars = new List<char>();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter) break;
            if (key.Key == ConsoleKey.Backspace)
            {
                if (chars.Count > 0)
                {
                    chars.RemoveAt(chars.Count - 1);
                    Console.Error.Write("\b \b");
                }

                continue;
            }

            if (!char.IsControl(key.KeyChar))
            {
                chars.Add(key.KeyChar);
                Console.Error.Write('*');
            }
        }

        return new string([.. chars]).Trim();
    }

    /// <summary><c>&lt;scheme&gt;_&lt;prefix&gt;_****</c>: the prefix is a non-secret lookup handle, the rest stays hidden.</summary>
    public static string Mask(string token)
    {
        var parts = token.Split('_');
        return parts.Length >= 3 ? $"{parts[0]}_{parts[1]}_****" : "****";
    }
}
