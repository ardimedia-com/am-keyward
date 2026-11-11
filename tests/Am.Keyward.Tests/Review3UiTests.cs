using System.Xml.Linq;
using Am.Keyward.Core.Application;
using Am.Keyward.Ui.Blazor;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging;
using NSubstitute;

namespace Am.Keyward.Tests;

/// <summary>
/// Review 3, area UI: the helpers behind the RCL fixes — which exception text a user may see (M30), which stored URL
/// may become a link (M28), the delayed re-hide of revealed secrets and issued tokens (M29) — and that every UI string
/// exists in every shipped language.
/// </summary>
[TestClass]
public class Review3UiTests
{
    private static readonly string[] Languages = ["de", "fr", "it", "es", "pt"];

    [TestMethod, TestCategory("Ui")]
    public void A_domain_message_thrown_by_keyward_code_is_shown()
    {
        var exception = Capture(() => throw new InvalidOperationException("A vault with this name already exists."));

        var text = UserFacingError.Describe(exception, Localizer(), Substitute.For<ILogger>());

        Assert.AreEqual("Common.Error" + "A vault with this name already exists.", text);
    }

    [TestMethod, TestCategory("Ui")]
    public void A_throw_helper_called_by_keyward_code_still_counts_as_keyward()
    {
        var exception = Capture(() => ArgumentException.ThrowIfNullOrWhiteSpace(" "));

        Assert.IsTrue(UserFacingError.IsDomainMessage(exception));
    }

    [TestMethod, TestCategory("Ui")]
    public void The_same_exception_type_thrown_inside_the_framework_is_hidden_and_logged()
    {
        // InvalidOperationException from the BCL ("Collection was modified"), not from Keyward.
        var exception = Capture(() =>
        {
            var list = new List<int> { 1 };
            foreach (var item in list)
            {
                list.Add(item);
            }
        });
        var logger = Substitute.For<ILogger>();

        var text = UserFacingError.Describe(exception, Localizer(), logger);

        Assert.AreEqual("Common.Error.Unexpected", text);
        Assert.AreEqual(1, ErrorLogs(logger));
    }

    [TestMethod, TestCategory("Ui")]
    public void An_unexpected_exception_type_is_hidden_and_logged()
    {
        var exception = Capture(() => throw new NullReferenceException("Object reference not set; at C:\\secret\\path"));
        var logger = Substitute.For<ILogger>();

        var text = UserFacingError.Describe(exception, Localizer(), logger);

        Assert.AreEqual("Common.Error.Unexpected", text);
        Assert.IsFalse(text.Contains("secret", StringComparison.Ordinal));
        Assert.AreEqual(1, ErrorLogs(logger));
    }

    [TestMethod, TestCategory("Ui")]
    public void A_version_conflict_gets_the_localized_conflict_text()
    {
        var keyward = Capture(() => throw new VaultItemVersionConflictException(Guid.NewGuid()));
        var ef = Capture(() => throw new Microsoft.EntityFrameworkCore.DbUpdateConcurrencyException("row changed"));

        Assert.AreEqual("Common.Error.Conflict", UserFacingError.Describe(keyward, Localizer(), Substitute.For<ILogger>()));
        Assert.AreEqual("Common.Error.Conflict", UserFacingError.Describe(ef, Localizer(), Substitute.For<ILogger>()));
    }

    [TestMethod, TestCategory("Ui")]
    [DataRow("https://example.com/login", "https://example.com/login")]
    [DataRow("  http://intranet.local:8080/a?b=c  ", "http://intranet.local:8080/a?b=c")]
    [DataRow("HTTPS://EXAMPLE.COM", "https://example.com/")]
    public void Absolute_http_urls_become_links(string stored, string expected)
    {
        Assert.AreEqual(expected, SafeHttpLink.ForHref(stored));
    }

    [TestMethod, TestCategory("Ui")]
    [DataRow("javascript:alert(document.cookie)")]
    [DataRow("JavaScript:alert(1)")]
    [DataRow("data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==")]
    [DataRow("vbscript:msgbox(1)")]
    [DataRow("file:///C:/Windows/win.ini")]
    [DataRow("ftp://example.com")]
    [DataRow("example.com")]
    [DataRow("/relative/path")]
    [DataRow("")]
    [DataRow(null)]
    public void Anything_else_stays_plain_text(string? stored)
    {
        Assert.IsNull(SafeHttpLink.ForHref(stored));
    }

    [TestMethod, TestCategory("Ui")]
    public async Task A_scheduled_action_runs_after_its_delay()
    {
        using var delayed = new DelayedAction();
        var ran = new TaskCompletionSource();

        delayed.Schedule(TimeSpan.FromMilliseconds(20), () =>
        {
            ran.TrySetResult();
            return Task.CompletedTask;
        });

        await ran.Task.WaitAsync(TimeSpan.FromSeconds(5));
    }

    [TestMethod, TestCategory("Ui")]
    public async Task A_cancelled_or_rescheduled_action_does_not_run()
    {
        using var delayed = new DelayedAction();
        var runs = new List<string>();

        delayed.Schedule(TimeSpan.FromMilliseconds(50), () => Record(runs, "cancelled"));
        delayed.Cancel();
        delayed.Schedule(TimeSpan.FromMilliseconds(50), () => Record(runs, "replaced"));
        delayed.Schedule(TimeSpan.FromMilliseconds(50), () => Record(runs, "last"));

        await Task.Delay(400);

        CollectionAssert.AreEqual(new[] { "last" }, runs);
    }

    [TestMethod, TestCategory("Ui")]
    public async Task Disposing_drops_a_pending_action()
    {
        var runs = new List<string>();
        var delayed = new DelayedAction();
        delayed.Schedule(TimeSpan.FromMilliseconds(30), () => Record(runs, "after dispose"));

        delayed.Dispose();
        await Task.Delay(200);

        Assert.IsEmpty(runs);
    }

    [TestMethod, TestCategory("Ui")]
    public void Every_ui_string_exists_in_every_language()
    {
        var english = Keys(ResourceFile(""));
        foreach (var language in Languages)
        {
            var translated = Keys(ResourceFile("." + language));
            var missing = english.Except(translated).Order().ToList();
            var extra = translated.Except(english).Order().ToList();
            Assert.IsEmpty(missing, $"{language}: missing {string.Join(", ", missing)}");
            Assert.IsEmpty(extra, $"{language}: not in the English file {string.Join(", ", extra)}");
        }
    }

    [TestMethod, TestCategory("Ui")]
    public void German_texts_use_swiss_spelling()
    {
        var offending = XDocument.Load(ResourceFile(".de")).Root!.Elements("data")
            .Where(d => (d.Element("value")?.Value ?? "").Contains('ß', StringComparison.Ordinal))
            .Select(d => (string)d.Attribute("name")!)
            .ToList();

        Assert.IsEmpty(offending, string.Join(", ", offending));
    }

    private static Task Record(List<string> runs, string name)
    {
        lock (runs)
        {
            runs.Add(name);
        }

        return Task.CompletedTask;
    }

    private static int ErrorLogs(ILogger logger) =>
        logger.ReceivedCalls().Count(c => c.GetMethodInfo().Name == nameof(ILogger.Log) && c.GetArguments()[0] is LogLevel.Error);

    private static Exception Capture(Action action)
    {
        try
        {
            action();
        }
        catch (Exception exception)
        {
            return exception;
        }

        throw new AssertFailedException("The action did not throw.");
    }

    // Returns the key itself, so the tests see which text was chosen.
    private static IStringLocalizer Localizer()
    {
        var localizer = Substitute.For<IStringLocalizer>();
        localizer[Arg.Any<string>()].Returns(call => new LocalizedString((string)call[0], (string)call[0]));
        return localizer;
    }

    private static HashSet<string> Keys(string path) =>
        [.. XDocument.Load(path).Root!.Elements("data").Select(d => (string)d.Attribute("name")!)];

    private static string ResourceFile(string suffix)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            var candidate = Path.Combine(directory.FullName, "src", "Am.Keyward.Ui.Blazor", "Resources", $"SharedResource{suffix}.resx");
            if (File.Exists(candidate))
            {
                return candidate;
            }

            directory = directory.Parent;
        }

        throw new FileNotFoundException($"SharedResource{suffix}.resx not found above {AppContext.BaseDirectory}");
    }
}
