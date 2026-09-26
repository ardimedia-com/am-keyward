using System.ComponentModel;
using System.Text;
using Am.Keyward.Contracts;
using ModelContextProtocol.Server;

namespace Am.Keyward.Mcp;

/// <summary>
/// The MCP tools. Every answer is plain text for the assistant and NEVER contains a secret value: creating and
/// updating send values without echoing them, and a revealed value goes to the clipboard only.
/// </summary>
[McpServerToolType]
internal sealed class KeywardTools(KeywardAgentClient keyward, ISecretClipboard clipboard)
{
    public static readonly TimeSpan ClipboardLifetime = TimeSpan.FromSeconds(30);

    [McpServerTool(Name = "list_vaults", ReadOnly = true), Description("Lists the KEYWARD vaults this agent token may reach.")]
    public async Task<string> ListVaultsAsync(CancellationToken ct)
    {
        var result = await keyward.ListVaultsAsync(ct);
        if (!result.Ok) return result.Error!;
        return result.Value is { Count: > 0 } vaults
            ? string.Join('\n', vaults.Select(v => $"{v.Id}  {v.Name}"))
            : "No vault is reachable with this token.";
    }

    [McpServerTool(Name = "list_items", ReadOnly = true), Description("Lists the folders and entries (names and types only) of one vault.")]
    public async Task<string> ListItemsAsync([Description("The vault id from list_vaults.")] Guid vaultId, CancellationToken ct)
    {
        var result = await keyward.TreeAsync(vaultId, ct);
        if (!result.Ok) return result.Error!;

        var tree = result.Value!;
        var text = new StringBuilder($"Vault «{tree.VaultName}» ({tree.VaultId})\n");
        void Write(Guid? folderId, string indent)
        {
            foreach (var folder in tree.Folders.Where(f => f.ParentFolderId == folderId).OrderBy(f => f.Name))
            {
                text.AppendLine($"{indent}[folder] {folder.Name}  ({folder.Id})");
                Write(folder.Id, indent + "  ");
            }

            foreach (var item in tree.Items.Where(i => i.FolderId == folderId).OrderBy(i => i.Name))
            {
                text.AppendLine($"{indent}{item.Name}  [{item.Type}]  ({item.Id})");
            }
        }

        Write(null, "  ");
        return text.ToString().TrimEnd();
    }

    [McpServerTool(Name = "search", ReadOnly = true), Description("Finds entries by name across the reachable vaults (at least 2 characters).")]
    public async Task<string> SearchAsync([Description("Part of the entry name.")] string query, CancellationToken ct)
    {
        var result = await keyward.SearchAsync(query, ct);
        if (!result.Ok) return result.Error!;
        return result.Value is { Count: > 0 } hits
            ? string.Join('\n', hits.Select(h => $"{h.Name}  [{h.Type}]  ({h.Id}, vault {h.VaultId})"))
            : "No entry matches.";
    }

    [McpServerTool(Name = "get_item", ReadOnly = true), Description("Shows one entry without its secret: name, type, link, version and — for a Login — URL and user name.")]
    public async Task<string> GetItemAsync([Description("The entry id.")] Guid itemId, CancellationToken ct)
    {
        var result = await keyward.GetItemAsync(itemId, ct);
        if (!result.Ok) return result.Error!;

        var item = result.Value!;
        var text = new StringBuilder()
            .AppendLine($"{item.Name}  [{item.Type}]  ({item.Id})")
            .AppendLine($"Link: {keyward.AbsoluteLink(item.Link)}")
            .AppendLine($"Version: {item.VersionId}");
        if (item.Url is not null) text.AppendLine($"URL: {item.Url}");
        if (item.Username is not null) text.AppendLine($"User name: {item.Username}");
        return text.ToString().TrimEnd();
    }

    [McpServerTool(Name = "create_login"), Description("Stores a Login (URL, user name, password, note) in a vault. The password is never shown back; the answer is the entry link to give to the person.")]
    public async Task<string> CreateLoginAsync(
        [Description("The vault id from list_vaults.")] Guid vaultId,
        [Description("Entry name, e.g. the service.")] string name,
        [Description("Sign-in URL.")] string? url = null,
        [Description("User name.")] string? username = null,
        [Description("Password.")] string? password = null,
        [Description("Note, e.g. where the credential came from.")] string? note = null,
        [Description("Optional folder id from list_items.")] Guid? folderId = null,
        CancellationToken ct = default)
    {
        var result = await keyward.CreateItemAsync(vaultId, new AgentCreateItemRequest("Login", name, folderId, url, username, password, note), ct);
        return result.Ok ? Written("Stored", result.Value!) : result.Error!;
    }

    [McpServerTool(Name = "create_item"), Description("Stores a non-Login entry: SecureNote, ApiCredential, ConnectionString or Generic. The value is never shown back.")]
    public async Task<string> CreateItemAsync(
        [Description("The vault id from list_vaults.")] Guid vaultId,
        [Description("SecureNote, ApiCredential, ConnectionString or Generic.")] string type,
        [Description("Entry name.")] string name,
        [Description("The secret value or note text.")] string value,
        [Description("Optional folder id from list_items.")] Guid? folderId = null,
        CancellationToken ct = default)
    {
        var result = await keyward.CreateItemAsync(vaultId, new AgentCreateItemRequest(type, name, folderId, Value: value), ct);
        return result.Ok ? Written("Stored", result.Value!) : result.Error!;
    }

    [McpServerTool(Name = "update_item"), Description("Changes an entry. A Login changes field by field (fields left out stay as they are); other types change their whole value. Pass the version from get_item so a change made in between is not overwritten.")]
    public async Task<string> UpdateItemAsync(
        [Description("The entry id.")] Guid itemId,
        [Description("The version from get_item. If omitted, the current version is used.")] Guid? versionId = null,
        [Description("New name.")] string? name = null,
        [Description("Login: new URL.")] string? url = null,
        [Description("Login: new user name.")] string? username = null,
        [Description("Login: new password.")] string? password = null,
        [Description("Login: new note.")] string? note = null,
        [Description("Other types: the new value.")] string? value = null,
        CancellationToken ct = default)
    {
        var version = versionId;
        if (version is null)
        {
            var current = await keyward.GetItemAsync(itemId, ct);
            if (!current.Ok) return current.Error!;
            version = current.Value!.VersionId;
        }

        var result = await keyward.UpdateItemAsync(itemId, version.Value, new AgentUpdateItemRequest(name, url, username, password, note, value), ct);
        return result.Ok ? Written("Updated", result.Value!) : result.Error!;
    }

    [McpServerTool(Name = "request_reveal"), Description("Asks to see one secret: 'Password' or 'Note' of a Login, 'Value' of other types. The person the token belongs to must approve it in KEYWARD (Agent tokens page) within 5 minutes; then call consume_reveal. The value is copied to the clipboard, never returned to you.")]
    public async Task<string> RequestRevealAsync(
        [Description("The entry id.")] Guid itemId,
        [Description("Password, Note or Value.")] string field,
        [Description("Why the value is needed — shown to the person who decides.")] string reason,
        CancellationToken ct)
    {
        if (!clipboard.IsAvailable)
        {
            return "Revealing needs the Windows clipboard, which is not available here; nothing was requested.";
        }

        var result = await keyward.RequestRevealAsync(itemId, new AgentRevealRequestBody(field, reason), ct);
        if (!result.Ok) return result.Error!;

        var request = result.Value!;
        return $"Reveal request {request.Id} is waiting for approval until {request.ExpiresAt:HH:mm} UTC. "
            + "Ask the person to approve it in KEYWARD under «Agent tokens», then call consume_reveal with this id.";
    }

    [McpServerTool(Name = "consume_reveal"), Description("After the person approved a reveal request: copies the value to the Windows clipboard (cleared after 30 seconds, kept out of clipboard history). The value itself is not returned. Works once.")]
    public async Task<string> ConsumeRevealAsync([Description("The id from request_reveal.")] Guid requestId, CancellationToken ct)
    {
        if (!clipboard.IsAvailable)
        {
            return "Revealing needs the Windows clipboard, which is not available here.";
        }

        var state = await keyward.GetRevealAsync(requestId, ct);
        if (!state.Ok) return state.Error!;
        switch (state.Value!.Status)
        {
            case "Pending":
                return $"Not approved yet — the person can decide until {state.Value.ExpiresAt:HH:mm} UTC. Try again after they approved.";
            case "Approved":
                break;
            default:
                return $"The request is {state.Value.Status}; nothing to copy. Ask again with request_reveal if still needed.";
        }

        var result = await keyward.ConsumeRevealAsync(requestId, ct);
        if (!result.Ok) return result.Error!;

        clipboard.CopyAndClearLater(result.Value!.Value, ClipboardLifetime);
        return $"The {result.Value.Field.ToLowerInvariant()} is on the clipboard for {ClipboardLifetime.TotalSeconds:0} seconds. "
            + "Tell the person to paste it now; the value was not shared with you.";
    }

    private string Written(string verb, AgentItemWrittenResponse written) =>
        $"{verb}: {written.Id} (version {written.VersionId}). Link for the person: {keyward.AbsoluteLink(written.Link)}";
}
