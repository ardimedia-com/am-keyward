using Am.Keyward.Core.Abstractions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Am.Keyward.Infrastructure.Auth;

/// <summary>
/// Out-of-band, append-only break-glass sink backed by a JSON-lines file outside the application database.
/// Each line carries the previous line's hash plus its own (<c>hash = SHA-256(prevHash | canonical-record)</c>),
/// so any deletion or edit of the file breaks the chain and is detectable — giving non-repudiation
/// independent of the database. Registered as a singleton.
///
/// <para>The file mechanics live in <see cref="HashChainedJsonLinesFile"/>: an exclusive file lock with the chain head
/// re-read on every append (two instances writing one file cannot fork the chain), and a torn last line is skipped
/// and reported instead of blocking every later break-glass event. <see cref="VerifyAsync"/> checks the whole trail;
/// the ops monitor runs it on every pass.</para>
///
/// <para><b>The path must be chosen.</b> Outside Development an unset <see cref="BreakGlassOptions.SinkFilePath"/>
/// is a configuration error (<see cref="BreakGlassOptions.ResolveSinkFilePath"/>): a trail in whatever the working
/// directory happens to be is lost on the next deploy, which is the opposite of non-repudiation.</para>
/// </summary>
public sealed class FileBreakGlassSink : IBreakGlassSink
{
    private readonly HashChainedJsonLinesFile _file;

    public FileBreakGlassSink(
        IOptions<BreakGlassOptions> options,
        IHostEnvironment? environment = null,
        ILogger<FileBreakGlassSink>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        _file = new HashChainedJsonLinesFile(options.Value.ResolveSinkFilePath(environment), logger);
    }

    /// <summary>The absolute path of the trail.</summary>
    public string FilePath => _file.Path;

    public async Task AppendAsync(BreakGlassRecord record, CancellationToken ct = default) =>
        await _file.AppendAsync(record, ct).ConfigureAwait(false);

    /// <summary>Verifies the whole trail (see <see cref="HashChainedJsonLinesFile.VerifyAsync"/>).</summary>
    public Task<HashChainVerification> VerifyAsync(CancellationToken ct = default) => _file.VerifyAsync(ct);
}
