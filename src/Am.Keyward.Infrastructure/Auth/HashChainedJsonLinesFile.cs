using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace Am.Keyward.Infrastructure.Auth;

/// <summary>The result of verifying a hash-chained JSON-lines file (<see cref="HashChainedJsonLinesFile.VerifyAsync"/>).</summary>
/// <param name="IsIntact">Every valid line links to the previous valid line and its hash recomputes.</param>
/// <param name="ValidLines">Lines that parsed and verified.</param>
/// <param name="DamagedLines">1-based numbers of lines that could not be parsed (e.g. a crash mid-append). They are skipped; the chain
/// is judged on the valid lines around them, so a damaged line alone does not break it — but it is reported.</param>
/// <param name="FirstBrokenLine">1-based number of the first line whose link or hash does not verify; <c>null</c> when intact.</param>
/// <param name="HeadHash">Hash of the last valid line (the genesis hash for an empty or missing file).</param>
/// <param name="Detail">What broke, for the operator.</param>
public sealed record HashChainVerification(
    bool IsIntact,
    int ValidLines,
    IReadOnlyList<int> DamagedLines,
    int? FirstBrokenLine,
    string HeadHash,
    string? Detail);

/// <summary>
/// An append-only, hash-chained JSON-lines file: each line is <c>{"record":…,"prevHash":…,"hash":…}</c> with
/// <c>hash = SHA-256(prevHash | record-json)</c>, so deleting, reordering or editing a line breaks the chain. Shared by
/// the break-glass trail and the audit head anchors.
///
/// <para><b>Safe with several writers.</b> Every append takes an exclusive write lock on the file (other writers wait
/// and retry; readers may still read) and re-reads the chain head from the file under that lock, so two processes or
/// two instances appending to one file can never fork the chain — nothing is cached between appends.</para>
///
/// <para><b>Survives a torn write.</b> A line left incomplete by a crash mid-append (or any unparsable line) is not
/// fatal: it is logged loudly, terminated so the next line starts cleanly, skipped when looking for the head, and
/// reported by <see cref="VerifyAsync"/> as a damaged line — the trail keeps working instead of refusing every later
/// event until someone repairs the file by hand.</para>
/// </summary>
public sealed class HashChainedJsonLinesFile
{
    /// <summary>The previous-hash of the first line.</summary>
    public const string GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000";

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private static readonly byte[] NewLine = Encoding.UTF8.GetBytes(Environment.NewLine);

    /// <summary>How long an append waits for another writer's lock before it gives up.</summary>
    private static readonly TimeSpan LockTimeout = TimeSpan.FromSeconds(30);

    /// <summary>How much of the file's end is read to find the head before falling back to the whole file.</summary>
    private const int TailWindow = 256 * 1024;

    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly ILogger? _logger;

    public HashChainedJsonLinesFile(string path, ILogger? logger = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        Path = System.IO.Path.GetFullPath(path);
        _logger = logger;
    }

    /// <summary>The absolute path of the file.</summary>
    public string Path { get; }

    /// <summary>
    /// Appends <paramref name="record"/> as the next link and returns its hash. Creates the file (and its folder) on
    /// first use. Throws <see cref="IOException"/> when the file stays locked by another writer for longer than 30 s.
    /// </summary>
    public async Task<string> AppendAsync<T>(T record, CancellationToken ct = default)
    {
        string canonical = JsonSerializer.Serialize(record, Json);

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            string? folder = System.IO.Path.GetDirectoryName(Path);
            if (!string.IsNullOrEmpty(folder))
            {
                Directory.CreateDirectory(folder);
            }

            await using FileStream stream = await this.OpenExclusiveAsync(ct).ConfigureAwait(false);
            Tail tail = await ReadTailAsync(stream, ct).ConfigureAwait(false);

            if (tail.UnparsableTailLines > 0)
            {
                _logger?.LogError(
                    "KEYWARD: the hash-chained file {Path} ends with {Count} unparsable line(s) (a write interrupted by a "
                    + "crash, or tampering). They are kept for inspection and skipped; the chain continues from the last "
                    + "valid line. Verify the file and investigate.",
                    Path, tail.UnparsableTailLines);
            }

            string hash = Hash(tail.HeadHash, canonical);
            byte[] line = Encoding.UTF8.GetBytes(BuildLine(canonical, tail.HeadHash, hash));

            stream.Seek(0, SeekOrigin.End);
            if (stream.Length > 0 && !tail.EndsWithNewLine)
            {
                // Terminate a torn last line, so it stays one damaged line instead of corrupting ours.
                await stream.WriteAsync(NewLine, ct).ConfigureAwait(false);
            }

            await stream.WriteAsync(line, ct).ConfigureAwait(false);
            await stream.WriteAsync(NewLine, ct).ConfigureAwait(false);
            await stream.FlushAsync(ct).ConfigureAwait(false);
            stream.Flush(flushToDisk: true);
            return hash;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Reads the whole file and verifies the chain: every valid line must link to the previous valid line's hash
    /// and its own hash must recompute. Unparsable lines are reported, not fatal. A missing file is intact and empty.
    /// </summary>
    public async Task<HashChainVerification> VerifyAsync(CancellationToken ct = default)
    {
        List<ParsedLine> lines = [];
        List<int> damaged = [];
        await foreach ((int number, ParsedLine? parsed) in this.ReadAllAsync(ct).ConfigureAwait(false))
        {
            if (parsed is null)
            {
                damaged.Add(number);
            }
            else
            {
                lines.Add(parsed);
            }
        }

        string previous = GenesisHash;
        int valid = 0;
        foreach (ParsedLine line in lines)
        {
            if (!string.Equals(line.PrevHash, previous, StringComparison.Ordinal))
            {
                return new HashChainVerification(false, valid, damaged, line.Number, previous,
                    $"Line {line.Number} does not link to the previous valid line (a line was removed, reordered or inserted).");
            }

            if (!string.Equals(Hash(line.PrevHash, line.RecordJson), line.Hash, StringComparison.Ordinal))
            {
                return new HashChainVerification(false, valid, damaged, line.Number, previous,
                    $"Line {line.Number} was altered: its hash does not recompute.");
            }

            previous = line.Hash;
            valid++;
        }

        string? detail = damaged.Count > 0
            ? $"{damaged.Count} unparsable line(s) skipped (line {string.Join(", ", damaged.Take(10))}); the chain around them verifies."
            : null;
        return new HashChainVerification(true, valid, damaged, null, previous, detail);
    }

    /// <summary>Every valid record in file order, as raw JSON; unparsable lines are skipped.</summary>
    public async IAsyncEnumerable<JsonElement> ReadRecordsAsync([System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct = default)
    {
        await foreach ((int _, ParsedLine? parsed) in this.ReadAllAsync(ct).ConfigureAwait(false))
        {
            if (parsed is not null)
            {
                using JsonDocument document = JsonDocument.Parse(parsed.RecordJson);
                yield return document.RootElement.Clone();
            }
        }
    }

    private async IAsyncEnumerable<(int Number, ParsedLine? Parsed)> ReadAllAsync(
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        if (!File.Exists(Path))
        {
            yield break;
        }

        await using FileStream stream = new(Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete,
            bufferSize: 4096, FileOptions.Asynchronous | FileOptions.SequentialScan);
        using StreamReader reader = new(stream, Encoding.UTF8);
        int number = 0;
        while (await reader.ReadLineAsync(ct).ConfigureAwait(false) is { } text)
        {
            number++;
            if (string.IsNullOrWhiteSpace(text))
            {
                continue;
            }

            yield return (number, TryParse(text, number));
        }
    }

    private async Task<FileStream> OpenExclusiveAsync(CancellationToken ct)
    {
        DateTimeOffset giveUpAt = DateTimeOffset.UtcNow + LockTimeout;
        TimeSpan pause = TimeSpan.FromMilliseconds(20);
        while (true)
        {
            try
            {
                // FileShare.Read: verifiers may read meanwhile; any other writer gets a sharing violation and waits.
                return new FileStream(Path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.Read,
                    bufferSize: 4096, FileOptions.Asynchronous | FileOptions.WriteThrough);
            }
            catch (IOException) when (File.Exists(Path) && DateTimeOffset.UtcNow < giveUpAt)
            {
                await Task.Delay(pause, ct).ConfigureAwait(false);
                pause = TimeSpan.FromMilliseconds(Math.Min(pause.TotalMilliseconds * 2, 500));
            }
        }
    }

    /// <summary>Finds the hash of the last valid line, reading only the end of the file when that suffices.</summary>
    private static async Task<Tail> ReadTailAsync(FileStream stream, CancellationToken ct)
    {
        long length = stream.Length;
        if (length == 0)
        {
            return new Tail(GenesisHash, EndsWithNewLine: true, UnparsableTailLines: 0);
        }

        stream.Seek(length - 1, SeekOrigin.Begin);
        byte[] last = new byte[1];
        await stream.ReadExactlyAsync(last, ct).ConfigureAwait(false);
        bool endsWithNewLine = last[0] == (byte)'\n';

        long window = Math.Min(length, TailWindow);
        while (true)
        {
            byte[] buffer = new byte[window];
            stream.Seek(length - window, SeekOrigin.Begin);
            await stream.ReadExactlyAsync(buffer, ct).ConfigureAwait(false);

            string[] lines = Encoding.UTF8.GetString(buffer).Split('\n');
            // Unless the window starts at the beginning of the file, its first line may be cut: ignore it.
            int first = window == length ? 0 : 1;
            int unparsable = 0;
            for (int i = lines.Length - 1; i >= first; i--)
            {
                string text = lines[i].TrimEnd('\r');
                if (string.IsNullOrWhiteSpace(text))
                {
                    continue;
                }

                if (TryParse(text, 0) is { } parsed)
                {
                    return new Tail(parsed.Hash, endsWithNewLine, unparsable);
                }

                unparsable++;
            }

            if (window == length)
            {
                // No valid line at all: the chain starts over from genesis (the damaged lines stay in the file).
                return new Tail(GenesisHash, endsWithNewLine, unparsable);
            }

            window = length;
        }
    }

    private static ParsedLine? TryParse(string text, int number)
    {
        try
        {
            using JsonDocument document = JsonDocument.Parse(text);
            JsonElement root = document.RootElement;
            if (root.ValueKind == JsonValueKind.Object
                && root.TryGetProperty("record", out JsonElement record)
                && root.TryGetProperty("prevHash", out JsonElement prevHash) && prevHash.ValueKind == JsonValueKind.String
                && root.TryGetProperty("hash", out JsonElement hash) && hash.ValueKind == JsonValueKind.String)
            {
                // The raw text of "record" is exactly what was hashed: it was written verbatim (see BuildLine).
                return new ParsedLine(number, record.GetRawText(), prevHash.GetString()!, hash.GetString()!);
            }
        }
        catch (JsonException)
        {
            // Unparsable: reported by the caller.
        }

        return null;
    }

    private static string BuildLine(string canonicalRecord, string prevHash, string hash)
    {
        using MemoryStream buffer = new();
        using (Utf8JsonWriter writer = new(buffer))
        {
            writer.WriteStartObject();
            writer.WritePropertyName("record");
            writer.WriteRawValue(canonicalRecord, skipInputValidation: false);
            writer.WriteString("prevHash", prevHash);
            writer.WriteString("hash", hash);
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    private static string Hash(string previousHash, string canonicalRecord) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(previousHash + '|' + canonicalRecord)));

    private sealed record ParsedLine(int Number, string RecordJson, string PrevHash, string Hash);

    private readonly record struct Tail(string HeadHash, bool EndsWithNewLine, int UnparsableTailLines);
}
