using System.Security.Cryptography;
using PasswordManager.Core.Models;
using PasswordManager.Core.Storage;
using PasswordManager.Core.UserManagement;
using Xunit;

namespace PasswordManager.Core.Tests;

public sealed class VaultSessionManagerTests
{
    private const string Master = "Correct-Master-Password-for-Stage4-Testing";
    private const string Incorrect = "Incorrect-Master-Password-Stage4-Testing";
    private const string Secret = "stage4-example-secret-4821";
    private static readonly TimeSpan IdleTime = TimeSpan.FromMinutes(5);

    private static CredentialInput Example(string title = "Example") => new()
    {
        Title = title,
        Username = "test-user",
        Password = Secret,
        Url = "https://example.invalid",
        Notes = "Synthetic test credential"
    };

    private static void CreateFixtureVault(VaultRepository repository)
    {
        // The tests use the minimum allowed KDF work factor, not a weakened
        // algorithm. The production CreateVault() method uses its defaults.
        using var vault = repository.CreateNewWithParameters(
            Master, Argon2idKeyDerivationTests.TestParameters());
    }

    private static VaultSessionManager NewSession(VaultRepository repository, ManualClock clock)
        => new(repository, clock, IdleTime, startBackgroundTimer: false);

    [Fact]
    public void StartsLockedAndDeniesCredentialOperations()
    {
        using var directory = new TemporaryDirectory();
        var clock = new ManualClock();
        using var session = NewSession(new VaultRepository(directory.Path), clock);

        Assert.False(session.IsUnlocked);
        Assert.Throws<InvalidOperationException>(() => session.ListEntries());
        Assert.Throws<InvalidOperationException>(() => session.AddCredential(Example()));
        Assert.Throws<InvalidOperationException>(() => session.GetCredential(Guid.NewGuid()));
        Assert.Throws<InvalidOperationException>(() => session.UpdateCredential(Guid.NewGuid(), Example()));
        Assert.Throws<InvalidOperationException>(() => session.DeleteCredential(Guid.NewGuid()));
        Assert.Throws<InvalidOperationException>(() => session.RegisterUserActivity());
    }

    [Fact]
    public void CorrectMasterPasswordUnlocksAndWrongPasswordDoesNot()
    {
        using var directory = new TemporaryDirectory();
        var repo = new VaultRepository(directory.Path);
        CreateFixtureVault(repo);
        using var session = NewSession(repo, new ManualClock());

        Assert.Throws<CryptographicException>(() => session.Unlock(Incorrect));
        Assert.False(session.IsUnlocked);
        Assert.Throws<InvalidOperationException>(() => session.ListEntries());
    }

    [Fact]
    public void CreateVaultStartsAuthenticatedSessionAndWritesEncryptedFile()
    {
        using var directory = new TemporaryDirectory();
        var repo = new VaultRepository(directory.Path);
        using var session = NewSession(repo, new ManualClock());

        Assert.False(session.VaultExists);
        session.CreateVault(Master); // Uses the actual production KDF settings.
        Assert.True(session.VaultExists);
        Assert.True(session.IsUnlocked);
        Assert.Throws<InvalidOperationException>(() => session.CreateVault(Master));
        session.Lock();

        Assert.True(File.Exists(System.IO.Path.Combine(directory.Path, "vault.spm")));
        session.Unlock(Master);
        Assert.Empty(session.ListEntries());
    }

    [Fact]
    public void ShortWrongPasswordFailsWithGenericAuthenticationError()
    {
        using var directory = new TemporaryDirectory();
        var repo = new VaultRepository(directory.Path);
        CreateFixtureVault(repo);
        using var session = NewSession(repo, new ManualClock());
        CryptographicException ex = Assert.Throws<CryptographicException>(() => session.Unlock("short"));
        Assert.Equal("Unable to unlock the vault.", ex.Message);
        Assert.False(session.IsUnlocked);
    }

    [Fact]
    public void FirstWrongPasswordCanBeFollowedImmediatelyByCorrectPassword()
    {
        using var directory = new TemporaryDirectory();
        var repo = new VaultRepository(directory.Path);
        CreateFixtureVault(repo);
        using var session = NewSession(repo, new ManualClock());

        Assert.Throws<CryptographicException>(() => session.Unlock(Incorrect));
        Assert.Equal(TimeSpan.Zero, session.UnlockRetryAfter);
        session.Unlock(Master);
        Assert.True(session.IsUnlocked);
        Assert.Equal(VaultLockReason.None, session.LastLockReason);
        Assert.Empty(session.ListEntries());
    }

    [Fact]
    public void RepeatedWrongPasswordsProduceNonBlockingCooldown()
    {
        using var directory = new TemporaryDirectory();
        var repo = new VaultRepository(directory.Path);
        CreateFixtureVault(repo);
        var clock = new ManualClock();
        using var session = NewSession(repo, clock);

        Assert.Throws<CryptographicException>(() => session.Unlock(Incorrect));
        Assert.Throws<CryptographicException>(() => session.Unlock(Incorrect));
        Assert.Equal(TimeSpan.FromSeconds(1), session.UnlockRetryAfter);
        Assert.Throws<InvalidOperationException>(() => session.Unlock(Master));
        Assert.False(session.IsUnlocked);

        clock.Advance(TimeSpan.FromSeconds(1));
        Assert.Equal(TimeSpan.Zero, session.UnlockRetryAfter);
        session.Unlock(Master);
        Assert.True(session.IsUnlocked);
        Assert.Equal(TimeSpan.Zero, session.UnlockRetryAfter);
    }

    [Fact]
    public void AddUpdateAndDeleteAreSavedBeforeSuccessIsReturned()
    {
        using var directory = new TemporaryDirectory();
        var repo = new VaultRepository(directory.Path);
        CreateFixtureVault(repo);
        var clock = new ManualClock();
        using var session = NewSession(repo, clock);
        session.Unlock(Master);

        Guid id = session.AddCredential(Example());
        Assert.Equal(id, Assert.Single(session.ListEntries()).Id);
        Assert.Equal(Secret, session.GetCredential(id).Password);
        Assert.True(session.UpdateCredential(id, Example("Updated title")));
        Assert.Equal("Updated title", session.GetCredential(id).Title);
        Assert.False(session.UpdateCredential(Guid.NewGuid(), Example()));
        session.Lock();

        // No explicit Save() call is needed through the session boundary.
        using (var reopened = repo.Open(Master))
        {
            Assert.Equal("Updated title", reopened.GetCredential(id).Title);
        }

        session.Unlock(Master);
        Assert.True(session.DeleteCredential(id));
        Assert.False(session.DeleteCredential(id));
        session.Lock();
        using var empty = repo.Open(Master);
        Assert.Empty(empty.ListEntries());
    }

    [Fact]
    public void ManualLockReleasesVaultAndBlocksAccess()
    {
        using var directory = new TemporaryDirectory();
        var repo = new VaultRepository(directory.Path);
        CreateFixtureVault(repo);
        using var session = NewSession(repo, new ManualClock());
        session.Unlock(Master);

        session.Lock();
        session.Lock(); // Idempotent.
        Assert.False(session.IsUnlocked);
        Assert.Equal(VaultLockReason.Manual, session.LastLockReason);
        Assert.Throws<InvalidOperationException>(() => session.ListEntries());
        using var other = repo.Open(Master); // OS vault lock was released.
        Assert.Empty(other.ListEntries());
    }

    [Fact]
    public void ExpiredSessionCannotBeRevivedByUserActivity()
    {
        using var directory = new TemporaryDirectory();
        var repo = new VaultRepository(directory.Path);
        CreateFixtureVault(repo);
        var clock = new ManualClock();
        using var session = NewSession(repo, clock);
        session.Unlock(Master);

        clock.Advance(IdleTime);
        Assert.Throws<InvalidOperationException>(() => session.RegisterUserActivity());
        Assert.False(session.IsUnlocked);
        Assert.Equal(VaultLockReason.Inactivity, session.LastLockReason);
        Assert.Throws<InvalidOperationException>(() => session.AddCredential(Example()));
        using var other = repo.Open(Master);
        Assert.Empty(other.ListEntries());
    }

    [Fact]
    public void MeaningfulActivityResetsTimeoutButStatusPollingDoesNot()
    {
        using var directory = new TemporaryDirectory();
        var repo = new VaultRepository(directory.Path);
        CreateFixtureVault(repo);
        var clock = new ManualClock();
        using var session = NewSession(repo, clock);
        session.Unlock(Master);

        clock.Advance(TimeSpan.FromMinutes(4));
        Assert.True(session.IsUnlocked); // No reset from reading status.
        session.RegisterUserActivity();
        clock.Advance(TimeSpan.FromMinutes(4));
        Assert.True(session.IsUnlocked);
        clock.Advance(TimeSpan.FromMinutes(1));
        Assert.False(session.IsUnlocked);
        Assert.Equal(VaultLockReason.Inactivity, session.LastLockReason);
    }

    [Fact]
    public void CredentialOperationCountsAsActivity()
    {
        using var directory = new TemporaryDirectory();
        var repo = new VaultRepository(directory.Path);
        CreateFixtureVault(repo);
        var clock = new ManualClock();
        using var session = NewSession(repo, clock);
        session.Unlock(Master);

        clock.Advance(TimeSpan.FromMinutes(4));
        Assert.Empty(session.ListEntries());
        clock.Advance(TimeSpan.FromMinutes(4));
        Assert.True(session.IsUnlocked);
        clock.Advance(TimeSpan.FromMinutes(1));
        Assert.False(session.IsUnlocked);
    }

    [Fact]
    public void ChangingTimeoutMayImmediatelyLockIdleSession()
    {
        using var directory = new TemporaryDirectory();
        var repo = new VaultRepository(directory.Path);
        CreateFixtureVault(repo);
        var clock = new ManualClock();
        using var session = NewSession(repo, clock);
        session.Unlock(Master);

        clock.Advance(TimeSpan.FromMinutes(2));
        session.SetInactivityTimeout(TimeSpan.FromMinutes(1));
        Assert.False(session.IsUnlocked);
        Assert.Equal(VaultLockReason.Inactivity, session.LastLockReason);
    }

    [Fact]
    public void InvalidTimeoutsAreRejected()
    {
        using var directory = new TemporaryDirectory();
        var repo = new VaultRepository(directory.Path);
        var clock = new ManualClock();
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new VaultSessionManager(repo, clock, TimeSpan.Zero, false));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new VaultSessionManager(repo, clock, TimeSpan.FromDays(2), false));
        using var session = NewSession(repo, clock);
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            session.SetInactivityTimeout(TimeSpan.FromSeconds(-1)));
    }

    [Fact]
    public void OpeningAlreadyUnlockedSessionIsNotAllowed()
    {
        using var directory = new TemporaryDirectory();
        var repo = new VaultRepository(directory.Path);
        CreateFixtureVault(repo);
        using var session = NewSession(repo, new ManualClock());
        session.Unlock(Master);
        Assert.Throws<InvalidOperationException>(() => session.Unlock(Master));
        Assert.Throws<InvalidOperationException>(() => session.CreateVault(Master));
        Assert.True(session.IsUnlocked);
    }

    [Fact]
    public void DisposeRevokesSessionAndFurtherCalls()
    {
        using var directory = new TemporaryDirectory();
        var repo = new VaultRepository(directory.Path);
        CreateFixtureVault(repo);
        var session = NewSession(repo, new ManualClock());
        session.Unlock(Master);
        session.Dispose();
        session.Dispose();

        Assert.Throws<ObjectDisposedException>(() => session.ListEntries());
        Assert.Throws<ObjectDisposedException>(() => { _ = session.IsUnlocked; });
        Assert.Throws<ObjectDisposedException>(() => session.Unlock(Master));
        using var other = repo.Open(Master);
        Assert.Empty(other.ListEntries());
    }

    [Fact]
    public void BackgroundTimerLocksIdleVaultWithoutUiCalls()
    {
        using var directory = new TemporaryDirectory();
        var repo = new VaultRepository(directory.Path);
        CreateFixtureVault(repo);
        using var session = new VaultSessionManager(repo, new StopwatchSessionClock(),
            TimeSpan.FromMilliseconds(100), startBackgroundTimer: true);
        session.Unlock(Master);

        Assert.True(SpinWait.SpinUntil(() => !session.IsUnlocked,
            TimeSpan.FromSeconds(5)));
        Assert.Equal(VaultLockReason.Inactivity, session.LastLockReason);
    }

    [Fact]
    public void AutoLockCountdown_IsReadOnlyAndExpiresAtTheRealDeadline()
    {
        using var directory = new TemporaryDirectory();
        var repository = new VaultRepository(directory.Path);
        CreateFixtureVault(repository);
        var clock = new ManualClock();
        using var session = NewSession(repository, clock);

        Assert.Equal(TimeSpan.Zero, session.TimeUntilAutoLock);
        session.Unlock(Master);
        Assert.Equal(IdleTime, session.TimeUntilAutoLock);

        clock.Advance(TimeSpan.FromMinutes(2));
        for (int i = 0; i < 10; i++)
            Assert.Equal(TimeSpan.FromMinutes(3), session.TimeUntilAutoLock);

        clock.Advance(TimeSpan.FromMinutes(3));
        Assert.Equal(TimeSpan.Zero, session.TimeUntilAutoLock);
        Assert.False(session.IsUnlocked);
        Assert.Equal(VaultLockReason.Inactivity, session.LastLockReason);
        Assert.Throws<InvalidOperationException>(() => session.ListEntries());
    }

    [Fact]
    public void ChangingAutoLockSetting_DoesNotCountAsUserActivity()
    {
        using var directory = new TemporaryDirectory();
        var repository = new VaultRepository(directory.Path);
        CreateFixtureVault(repository);
        var clock = new ManualClock();
        using var session = NewSession(repository, clock);
        session.Unlock(Master);

        clock.Advance(TimeSpan.FromMinutes(4));
        Assert.Equal(TimeSpan.FromMinutes(1), session.TimeUntilAutoLock);

        session.SetInactivityTimeout(TimeSpan.FromMinutes(6));
        Assert.Equal(TimeSpan.FromMinutes(2), session.TimeUntilAutoLock);

        clock.Advance(TimeSpan.FromMinutes(2));
        Assert.False(session.IsUnlocked);
        Assert.Equal(VaultLockReason.Inactivity, session.LastLockReason);
    }

    private sealed class ManualClock : ISessionClock
    {
        private long _ticks;
        public long GetTimestamp() => _ticks;
        public TimeSpan GetElapsedTime(long sinceTimestamp)
            => TimeSpan.FromTicks(_ticks - sinceTimestamp);
        public void Advance(TimeSpan duration)
        {
            if (duration < TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(duration));
            _ticks = checked(_ticks + duration.Ticks);
        }
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public string Path { get; } = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(), "SPM-Stage4-" + Guid.NewGuid().ToString("N"));

        public void Dispose()
        {
            try { if (Directory.Exists(Path)) Directory.Delete(Path, recursive: true); }
            catch (IOException) { /* Windows antivirus can briefly retain a handle. */ }
            catch (UnauthorizedAccessException) { /* Test fixture cleanup only. */ }
        }
    }
}
