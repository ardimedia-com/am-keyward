using System.ComponentModel;
using System.Text;
using Am.Keyward.Contracts;
using ModelContextProtocol.Server;

namespace Am.Keyward.Mcp;

/// <summary>
/// The MCP tools. Every answer is plain text for the assistant and NEVER contains a secret value: creating and
/// updating send values without echoing them, and a revealed value goes to the clipboard only. The application
/// tools set up an application for the software-client API and answer with the link where a person pastes the
/// values and issues the app token.
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

    [McpServerTool(Name = "move_item"), Description("Moves an entry into another folder and/or another reachable vault (folder ids from list_items). Entries cannot be deleted by an agent. The entry link stays the same.")]
    public async Task<string> MoveItemAsync(
        [Description("The entry id.")] Guid itemId,
        [Description("The target vault id (the same vault to change only the folder).")] Guid vaultId,
        [Description("The target folder id; omit for the vault's top level.")] Guid? folderId = null,
        CancellationToken ct = default)
    {
        var result = await keyward.MoveItemAsync(itemId, new AgentMoveItemRequest(vaultId, folderId), ct);
        return result.Ok ? Written("Moved", result.Value!) : result.Error!;
    }

    [McpServerTool(Name = "request_reveal"), Description("Asks to see one secret: 'Password' or 'Note' of a Login, 'Value' of other types. Often simpler: give the person the entry link from get_item — they open the entry in KEYWARD and copy the value themselves. A reveal must be approved by the person the token belongs to in KEYWARD (Agent tokens page) within 5 minutes; then call consume_reveal. The value is copied to the clipboard, never returned to you.")]
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
            + "Ask the person to approve it in KEYWARD under «Agent tokens», then call consume_reveal with this id. "
            + $"Or the person opens the entry and copies the value there: {keyward.AbsoluteLink(request.ItemLink)}";
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
                return $"The request is {state.Value.Status}; nothing to copy. Ask again with request_reveal if still needed, "
                    + $"or let the person copy the value from the entry: {keyward.AbsoluteLink(state.Value.ItemLink)}";
        }

        var result = await keyward.ConsumeRevealAsync(requestId, ct);
        if (!result.Ok) return result.Error!;

        clipboard.CopyAndClearLater(result.Value!.Value, ClipboardLifetime);
        return $"The {result.Value.Field.ToLowerInvariant()} is on the clipboard for {ClipboardLifetime.TotalSeconds:0} seconds. "
            + "Tell the person to paste it now; the value was not shared with you.";
    }

    [McpServerTool(Name = "list_applications", ReadOnly = true), Description("Lists the KEYWARD applications (software-client API) this agent token may manage: environments, keys and per environment whether a value is set. Never a value.")]
    public async Task<string> ListApplicationsAsync(CancellationToken ct)
    {
        var result = await keyward.ListApplicationsAsync(ct);
        if (!result.Ok) return result.Error!;
        return result.Value is { Count: > 0 } applications
            ? string.Join("\n\n", applications.Select(Describe))
            : "No application is reachable with this token.";
    }

    [McpServerTool(Name = "create_application"), Description("Creates an application for the software-client API (the token needs «may create new applications»). It starts with the tenant's default environments; environments listed here are added. Answers with the link for the person.")]
    public async Task<string> CreateApplicationAsync(
        [Description("Application name, e.g. the program that reads the secrets (Am.PionexCom.Cmd.BotWatch).")] string name,
        [Description("Environments it needs, e.g. [\"Production\"].")] string[]? environments = null,
        CancellationToken ct = default)
    {
        var result = await keyward.CreateApplicationAsync(new AgentCreateApplicationRequest(name, environments), ct);
        return result.Ok ? $"Created.\n{Describe(result.Value!)}" : result.Error!;
    }

    [McpServerTool(Name = "add_environment"), Description("Adds an environment (e.g. Staging) to an application.")]
    public async Task<string> AddEnvironmentAsync(
        [Description("The application id from list_applications.")] Guid applicationId,
        [Description("Environment name.")] string name,
        CancellationToken ct = default)
    {
        var result = await keyward.AddEnvironmentAsync(applicationId, new AgentAddEnvironmentRequest(name), ct);
        return result.Ok ? $"Environment added.\n{Describe(result.Value!)}" : result.Error!;
    }

    [McpServerTool(Name = "create_secret_key"), Description("Creates a secret key in an application as a placeholder («not set»), e.g. Section:ApiKey. The person pastes the value in KEYWARD via the returned link. Prefer this over set_secret_value whenever you do not legitimately hold the value.")]
    public async Task<string> CreateSecretKeyAsync(
        [Description("The application id from list_applications.")] Guid applicationId,
        [Description("The configuration key, e.g. PionexOwnerBotWatch:ApiKey.")] string key,
        CancellationToken ct = default)
    {
        var result = await keyward.CreateSecretAsync(applicationId, new AgentCreateSecretRequest(key), ct);
        return result.Ok
            ? $"Key {result.Value!.Key} created, not set yet. Link for the person to paste the value: {keyward.AbsoluteLink(result.Value.Link)}"
            : result.Error!;
    }

    [McpServerTool(Name = "set_secret_value"), Description("Sets a secret key's value in one environment, write-only (the value is never shown back). The value must NOT come from the chat unless the user explicitly provided it for exactly this purpose; if you do not legitimately hold it, use create_secret_key and give the person the link instead. Creates the key if it does not exist yet.")]
    public async Task<string> SetSecretValueAsync(
        [Description("The application id from list_applications.")] Guid applicationId,
        [Description("The configuration key, e.g. PionexOwnerBotWatch:ApiSecret.")] string key,
        [Description("The environment, e.g. Production.")] string environment,
        [Description("The value.")] string value,
        CancellationToken ct = default)
    {
        var current = await keyward.GetApplicationAsync(applicationId, ct);
        if (!current.Ok) return current.Error!;

        var existing = current.Value!.Keys.FirstOrDefault(k => string.Equals(k.Key, key, StringComparison.OrdinalIgnoreCase));
        var result = existing is null
            ? await keyward.CreateSecretAsync(applicationId, new AgentCreateSecretRequest(key, environment, value), ct)
            : await keyward.SetSecretValueAsync(applicationId, existing.Key, new AgentSetSecretValueRequest(environment, value),
                existing.Values.FirstOrDefault(v => string.Equals(v.Environment, environment, StringComparison.OrdinalIgnoreCase))?.VersionId, ct);
        return result.Ok
            ? $"Value of {result.Value!.Key} in {result.Value.Environment} set (version {result.Value.VersionId}). Link for the person: {keyward.AbsoluteLink(result.Value.Link)}"
            : result.Error!;
    }

    [McpServerTool(Name = "list_app_tokens", ReadOnly = true), Description("Lists an application's app tokens: name, environment, status, expiry, last access and heartbeat monitoring. Never a token value; issuing, rotating and revoking stay with people (link in list_applications).")]
    public async Task<string> ListAppTokensAsync([Description("The application id from list_applications.")] Guid applicationId, CancellationToken ct)
    {
        var result = await keyward.ListApplicationTokensAsync(applicationId, ct);
        if (!result.Ok) return result.Error!;
        if (result.Value is not { Count: > 0 } tokens) return "The application has no app tokens.";

        return string.Join('\n', tokens.Select(t =>
            $"{t.Name}  [{t.Environment}, {t.Status}]  ({t.Id})"
            + (t.ExpiresAt is { } expires ? $"  expires {expires:yyyy-MM-dd}" : "")
            + (t.LastAccessAt is { } last ? $"  last access {last:yyyy-MM-dd HH:mm} UTC from {t.LastAccessIp ?? "?"}" : "  never used")
            + (t.Monitor is { Enabled: true } m ? $"  monitor {m.State} (max silence {m.MaxSilenceMinutes} min)" : "")));
    }

    [McpServerTool(Name = "get_app_statistics", ReadOnly = true), Description("Shows an application's app-token access statistics: requests per day, client addresses and access alerts.")]
    public async Task<string> GetAppStatisticsAsync(
        [Description("The application id from list_applications.")] Guid applicationId,
        [Description("How many days back (1–90).")] int days = 30,
        CancellationToken ct = default)
    {
        var result = await keyward.GetApplicationStatisticsAsync(applicationId, days, ct);
        if (!result.Ok) return result.Error!;

        var stats = result.Value!;
        var text = new StringBuilder();
        foreach (var token in stats.Daily.GroupBy(d => d.TokenId))
        {
            text.AppendLine($"Token {token.Key}: {token.Sum(d => d.Requests)} requests in {days} days, last day {token.Max(d => d.Date):yyyy-MM-dd}");
        }

        foreach (var address in stats.Addresses)
        {
            text.AppendLine($"Token {address.TokenId}: {address.IpAddress} seen {address.FirstSeenAt:yyyy-MM-dd} – {address.LastSeenAt:yyyy-MM-dd}");
        }

        foreach (var alert in stats.Alerts)
        {
            text.AppendLine($"Alert {alert.Kind} for token {alert.TokenId} at {alert.CreatedAt:yyyy-MM-dd HH:mm} UTC{(alert.IpAddress is null ? "" : $" from {alert.IpAddress}")}");
        }

        return text.Length == 0 ? "No access recorded." : text.ToString().TrimEnd();
    }

    // Names, environments and «set / not set» only — the API never sends a value, and neither does this text.
    private string Describe(AgentApplicationResponse application)
    {
        var text = new StringBuilder()
            .AppendLine($"{application.Name}  ({application.Id}){(application.CreatedByThisToken ? "  [created by this token]" : "")}")
            .AppendLine($"  Environments: {string.Join(", ", application.Environments)}");
        if (application.Keys.Count == 0)
        {
            text.AppendLine("  Keys: none");
        }

        foreach (var key in application.Keys)
        {
            var states = key.Values.Select(v => $"{v.Environment}={(v.ValueSet ? "set" : "not set")}"
                + (v.RotateBy is { } rotateBy ? $" (renew by {rotateBy:yyyy-MM-dd})" : "")
                + (string.IsNullOrWhiteSpace(v.RotationNote) ? "" : $" [note: {v.RotationNote}]"));
            text.AppendLine($"  {key.Key}: {string.Join(", ", states)}");
        }

        text.AppendLine($"  Link (keys and values): {keyward.AbsoluteLink(application.Link)}")
            .Append($"  App tokens are issued by a person here: {keyward.AbsoluteLink(application.TokensLink)}");
        return text.ToString();
    }

    private string Written(string verb, AgentItemWrittenResponse written) =>
        $"{verb}: {written.Id} (version {written.VersionId}). Link for the person: {keyward.AbsoluteLink(written.Link)}";
}
