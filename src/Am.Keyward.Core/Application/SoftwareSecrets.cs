namespace Am.Keyward.Core.Application;

/// <summary>Stores (creates or versions) a software secret's value for one project environment.</summary>
public sealed record StoreSoftwareSecretCommand(
    Guid TenantId,
    Guid ProjectId,
    string Environment,
    string Key,
    string Value,
    Guid? ActorUserId);

/// <summary>Reads the current value of a software secret for one project environment.</summary>
public sealed record ReadSoftwareSecretQuery(
    Guid TenantId,
    Guid ProjectId,
    string Environment,
    string Key,
    Guid? ActorUserId);

/// <summary>Application service for the software-credentials use case (encrypt-and-store / read-and-decrypt).</summary>
public interface ISoftwareSecretService
{
    Task StoreAsync(StoreSoftwareSecretCommand command, CancellationToken ct = default);

    Task<string?> ReadAsync(ReadSoftwareSecretQuery query, CancellationToken ct = default);
}
