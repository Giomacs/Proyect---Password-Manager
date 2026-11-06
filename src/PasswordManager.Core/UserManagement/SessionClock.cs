using System.Diagnostics;

namespace PasswordManager.Core.UserManagement;

/// <summary>
/// Monotonic time source. Avoids changing idle/session policy if the wall clock changes.
/// Internal injection allows deterministic timeout tests without sleeping.
/// </summary>
internal interface ISessionClock
{
    long GetTimestamp();
    TimeSpan GetElapsedTime(long sinceTimestamp);
}

internal sealed class StopwatchSessionClock : ISessionClock
{
    public long GetTimestamp() => Stopwatch.GetTimestamp();

    public TimeSpan GetElapsedTime(long sinceTimestamp)
        => Stopwatch.GetElapsedTime(sinceTimestamp);
}
