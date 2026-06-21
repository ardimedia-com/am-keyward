using Am.Keyward.Core.Abstractions;

namespace Am.Keyward.Infrastructure;

public sealed class SystemClock : IClock
{
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}
