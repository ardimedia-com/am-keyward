using System.Security.Cryptography;
using Am.Keyward.Core.Abstractions;
using Am.Keyward.Core.Application;
using Am.Keyward.Infrastructure.Provisioning;
using Am.Keyward.Infrastructure.Software;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;

namespace Am.Keyward.Tests;

/// <summary>
/// The startup configuration overlay's failure isolation. A database holding ciphertext from a foreign key
/// ring — a production copy restored onto a dev or test machine — opens some secrets and throws on others,
/// and the overlay has to survive that with everything it CAN read.
/// </summary>
[TestClass]
public class MachineSecretOverlayTests
{
    #region Fields

    private const string Application = "Bvd.Li.Toolbox.Ui.App.Blazor";
    private static readonly Guid TenantId = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid ProjectId = Guid.Parse("22222222-2222-2222-2222-222222222222");

    #endregion

    #region Public Methods

    /// <summary>
    /// The regression this class exists for: catching around the whole read loop let the FIRST undecryptable
    /// secret end it, so every key listed after it silently never reached configuration — and which ones
    /// those were came down to listing order. The app then started half-configured with one warning line.
    /// </summary>
    [TestMethod]
    [TestCategory("Unit")]
    public async Task ReadAll_OneUndecryptableSecret_StillReturnsTheOthers()
    {
        ISoftwareSecretService secrets = Substitute.For<ISoftwareSecretService>();
        secrets.ListSecretsAsync(TenantId, ProjectId, Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<IReadOnlyList<SoftwareSecretSummary>>(
            [
                new SoftwareSecretSummary("A:First", ["Development"]),
                new SoftwareSecretSummary("B:Sealed:ByAnotherInstallation", ["Development"]),
                new SoftwareSecretSummary("C:After", ["Development"]),
            ]));

        secrets.ReadAsync(Arg.Any<ReadSoftwareSecretQuery>(), Arg.Any<CancellationToken>())
            .Returns(call => call.Arg<ReadSoftwareSecretQuery>().Key switch
            {
                // What AES-GCM raises when the value was sealed by a key this installation does not hold.
                "B:Sealed:ByAnotherInstallation" => throw new AuthenticationTagMismatchException(),
                string key => Task.FromResult<string?>("value-of-" + key),
            });

        IReadOnlyDictionary<string, string> result = await Build(secrets).ReadAllAsync(TestContext.CancellationTokenSource.Token);

        Assert.AreEqual(2, result.Count, "the readable secrets must survive an unreadable neighbour");
        Assert.AreEqual("value-of-A:First", result["A:First"]);
        Assert.AreEqual("value-of-C:After", result["C:After"], "the secret AFTER the failing one is the regression");
        Assert.IsFalse(result.ContainsKey("B:Sealed:ByAnotherInstallation"));
    }

    /// <summary>
    /// The surrounding read is a different matter: without the project there is nothing to enumerate, so an
    /// empty overlay is correct — the host then runs on its configured values, and says so.
    /// </summary>
    [TestMethod]
    [TestCategory("Unit")]
    public async Task ReadAll_ListingFails_ReturnsEmptyInsteadOfThrowing()
    {
        ISoftwareSecretService secrets = Substitute.For<ISoftwareSecretService>();
        secrets.ListSecretsAsync(TenantId, ProjectId, Arg.Any<CancellationToken>())
            .Returns<Task<IReadOnlyList<SoftwareSecretSummary>>>(_ => throw new InvalidOperationException("no connection"));

        IReadOnlyDictionary<string, string> result = await Build(secrets).ReadAllAsync(TestContext.CancellationTokenSource.Token);

        Assert.AreEqual(0, result.Count);
    }

    #endregion

    #region Properties

    public TestContext TestContext { get; set; } = null!;

    #endregion

    #region Private Methods

    private static KeywardMachineSecrets Build(ISoftwareSecretService secrets)
    {
        IProjectService projects = Substitute.For<IProjectService>();
        projects.ListAsync(TenantId, Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<IReadOnlyList<ProjectInfo>>(
                [new ProjectInfo(ProjectId, Application, DateTimeOffset.UnixEpoch, 1, 3, 0)]));

        IKeywardWorkspaceContext workspace = Substitute.For<IKeywardWorkspaceContext>();
        workspace.TenantId.Returns(TenantId);

        IKeywardHostEnvironment environment = Substitute.For<IKeywardHostEnvironment>();
        environment.EnvironmentName.Returns("Development");

        return new KeywardMachineSecrets(
            secrets,
            projects,
            workspace,
            Substitute.For<ITenantScopeSetter>(),
            Options.Create(new KeywardMachineSecretsOptions { ApplicationName = Application }),
            environment,
            NullLogger<KeywardMachineSecrets>.Instance);
    }

    #endregion
}
