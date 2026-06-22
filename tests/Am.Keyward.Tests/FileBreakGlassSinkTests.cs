using System.Text.Json;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Infrastructure.Auth;
using Microsoft.Extensions.Options;

namespace Am.Keyward.Tests;

/// <summary>
/// The file break-glass sink appends a tamper-evident, hash-chained JSON line per event: the first line
/// chains to the genesis hash and each subsequent line chains to the previous line's hash, so any deletion
/// or edit breaks the chain.
/// </summary>
[TestClass]
public class FileBreakGlassSinkTests
{
    [TestMethod, TestCategory("Unit")]
    public async Task Appends_a_hash_chained_line_per_event()
    {
        var path = Path.Combine(Path.GetTempPath(), $"bg-{Path.GetRandomFileName()}.jsonl");
        try
        {
            var sink = new FileBreakGlassSink(Options.Create(new BreakGlassOptions { SinkFilePath = path }));

            await sink.AppendAsync(new BreakGlassRecord(DateTimeOffset.UnixEpoch, "Requested", Guid.NewGuid(), null, "Vault:1", Guid.NewGuid(), null, "r1"));
            await sink.AppendAsync(new BreakGlassRecord(DateTimeOffset.UnixEpoch, "Approved", Guid.NewGuid(), null, "Vault:1", Guid.NewGuid(), Guid.NewGuid(), "r1"));

            var lines = await File.ReadAllLinesAsync(path);
            Assert.HasCount(2, lines);

            using var first = JsonDocument.Parse(lines[0]);
            using var second = JsonDocument.Parse(lines[1]);

            var genesis = new string('0', 64);
            Assert.AreEqual(genesis, first.RootElement.GetProperty("prevHash").GetString());

            var firstHash = first.RootElement.GetProperty("hash").GetString();
            Assert.AreEqual(firstHash, second.RootElement.GetProperty("prevHash").GetString(),
                "Each line must chain to the previous line's hash.");
            Assert.AreNotEqual(firstHash, second.RootElement.GetProperty("hash").GetString());
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }
}
