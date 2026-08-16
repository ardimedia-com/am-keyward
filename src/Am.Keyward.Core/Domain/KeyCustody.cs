namespace Am.Keyward.Core.Domain.KeyCustody;

/// <summary>
/// One row per database: a known plaintext, wrapped under the KEK of whichever installation created it.
/// Every later start unwraps it and compares — a direct proof that the key this process holds is the key
/// this data was sealed with.
///
/// <para>It exists because the alternative signals are all indirect. The stored <c>KekId</c> names the key's
/// FORMAT, so it cannot tell two keys of the same format apart; and a comparison of machine names or key
/// paths tests a recipe rather than the fact — a key file that was silently regenerated at the very same
/// path on the very same machine (a rebuilt server, a wiped ProgramData, a lost file) satisfies every such
/// rule and still cannot read a single stored value.</para>
///
/// <para>The canary catches all of it at startup instead of at the first read: a second installation
/// writing the same database under a different key, a regenerated key, and a database restored without its
/// key store. It is not a secret — it is a fixed, publicly known value; its ciphertext reveals nothing
/// beyond the fact that some key produced it.</para>
/// </summary>
public sealed class KekCanary
{
    /// <summary>The one and only row. A fixed key makes a concurrent second insert fail loudly instead of duplicating.</summary>
    public const int SingletonId = 1;

    public int Id { get; private set; }

    /// <summary>The <see cref="Abstractions.IKekProvider.KekId"/> in force when the canary was written.</summary>
    public string KekId { get; private set; }

    /// <summary>The known plaintext, wrapped by that KEK.</summary>
    public byte[] Wrapped { get; private set; }

    public DateTimeOffset CreatedAt { get; private set; }

    /// <summary>Machine and environment that wrote it — diagnostic only, so an operator can see where the first install ran.</summary>
    public string CreatedBy { get; private set; }

    public KekCanary(int id, string kekId, byte[] wrapped, DateTimeOffset createdAt, string createdBy)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(kekId);
        ArgumentNullException.ThrowIfNull(wrapped);

        Id = id;
        KekId = kekId;
        Wrapped = wrapped;
        CreatedAt = createdAt;
        CreatedBy = createdBy ?? string.Empty;
    }

    public static KekCanary Create(string kekId, byte[] wrapped, DateTimeOffset createdAt, string createdBy) =>
        new(SingletonId, kekId, wrapped, createdAt, createdBy);
}
