using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Am.Keyward.Core.Abstractions;
using Microsoft.Extensions.Options;

namespace Am.Keyward.Infrastructure.Auth;

/// <summary>
/// Out-of-band, append-only break-glass sink backed by a JSON-lines file outside the application database.
/// Each line carries the previous line's hash plus its own (<c>hash = SHA-256(prevHash | canonical-record)</c>),
/// so any deletion or edit of the file breaks the chain and is detectable — giving non-repudiation
/// independent of the database. Writes are serialized within the process; registered as a singleton.
/// </summary>
public sealed class FileBreakGlassSink : IBreakGlassSink, IDisposable
{
    private const string GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000";
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly string _path;
    private string? _lastHash;

    public FileBreakGlassSink(IOptions<BreakGlassOptions> options)
    {
        var configured = options.Value.SinkFilePath;
        _path = string.IsNullOrWhiteSpace(configured)
            ? Path.Combine(Directory.GetCurrentDirectory(), "breakglass-audit.jsonl")
            : configured;
    }

    public async Task AppendAsync(BreakGlassRecord record, CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var previousHash = _lastHash ??= await ReadLastHashAsync(ct).ConfigureAwait(false);
            var canonical = JsonSerializer.Serialize(record, Json);
            var hash = Convert.ToHexStringLower(
                SHA256.HashData(Encoding.UTF8.GetBytes(previousHash + '|' + canonical)));

            var line = JsonSerializer.Serialize(new ChainedLine(record, previousHash, hash), Json);
            await File.AppendAllTextAsync(_path, line + Environment.NewLine, ct).ConfigureAwait(false);
            _lastHash = hash;
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<string> ReadLastHashAsync(CancellationToken ct)
    {
        if (!File.Exists(_path))
        {
            return GenesisHash;
        }

        var lines = await File.ReadAllLinesAsync(_path, ct).ConfigureAwait(false);
        for (var i = lines.Length - 1; i >= 0; i--)
        {
            if (string.IsNullOrWhiteSpace(lines[i]))
            {
                continue;
            }

            var parsed = JsonSerializer.Deserialize<ChainedLine>(lines[i], Json);
            return parsed?.Hash ?? GenesisHash;
        }

        return GenesisHash;
    }

    public void Dispose() => _gate.Dispose();

    private sealed record ChainedLine(BreakGlassRecord Record, string PrevHash, string Hash);
}
