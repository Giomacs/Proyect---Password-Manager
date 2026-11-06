using System.Security.Cryptography;
using PasswordManager.Core.Models;
using PasswordManager.Core.Storage;

namespace PasswordManager.Core.UserManagement;

/// <summary>
/// Single-user offline session boundary for the WPF application.
/// Does not expose UnlockedVault or raw encryption keys to callers.
/// All credential operations are checked while holding the session lock.
/// </summary>
public sealed class VaultSessionManager : IDisposable
{
    public static readonly TimeSpan DefaultInactivityTimeout = TimeSpan.FromMinutes(5);
    public static readonly TimeSpan MaximumInactivityTimeout = TimeSpan.FromHours(24);

    private readonly object _gate = new();
    private readonly VaultRepository _repository;
    private readonly ISessionClock _clock;
    private readonly Timer? _timer;
    private UnlockedVault? _vault;
    private TimeSpan _inactivityTimeout;
    private long _lastActivity;
    private long _lastFailure;
    private int _failedUnlocks;
    private VaultLockReason _lastLockReason = VaultLockReason.None;
    private bool _disposed;

    /// <summary>
    /// Production session. Uses the fixed per-user vault location and a
    /// background timer that checks inactivity without requiring UI activity.
    /// </summary>
    public VaultSessionManager(TimeSpan? inactivityTimeout = null)
        : this(new VaultRepository(), new StopwatchSessionClock(),
            inactivityTimeout ?? DefaultInactivityTimeout, startBackgroundTimer: true)
    { }

    /// <summary>
    /// Only used by the internal test assembly to inject a temporary vault
    /// repository and a controllable monotonic clock.
    /// </summary>
    internal VaultSessionManager(VaultRepository repository, ISessionClock clock,
        TimeSpan inactivityTimeout, bool startBackgroundTimer)
    {
        _repository = repository ?? throw new ArgumentNullException(nameof(repository));
        _clock = clock ?? throw new ArgumentNullException(nameof(clock));
        ValidateTimeout(inactivityTimeout);
        _inactivityTimeout = inactivityTimeout;

        if (startBackgroundTimer)
        {
            // Timers are checks, not activity. Polling never extends the session.
            // Every public credential operation also checks expiry immediately.
            _timer = new Timer(static state => ((VaultSessionManager)state!).OnTimer(),
                this, dueTime: TimeSpan.FromMilliseconds(250),
                period: TimeSpan.FromMilliseconds(250));
        }
    }

    public bool VaultExists
    {
        get { lock (_gate) { EnsureNotDisposed(); return _repository.VaultExists; } }
    }

    public bool IsUnlocked
    {
        get
        {
            lock (_gate)
            {
                EnsureNotDisposed();
                ExpireIfIdle();
                return _vault is not null;
            }
        }
    }

    public VaultLockReason LastLockReason
    {
        get
        {
            lock (_gate)
            {
                EnsureNotDisposed();
                ExpireIfIdle();
                return _lastLockReason;
            }
        }
    }

    public TimeSpan InactivityTimeout
    {
        get { lock (_gate) { EnsureNotDisposed(); return _inactivityTimeout; } }
    }

    /// <summary>
    /// UI-only throttle. Does not defend against offline guesses and can be
    /// reset by restarting the process; Argon2id is the offline control.
    /// </summary>
    public TimeSpan UnlockRetryAfter
    {
        get
        {
            lock (_gate)
            {
                EnsureNotDisposed();
                return RemainingUnlockDelay();
            }
        }
    }

    /// <summary>
    /// Creates the first vault and leaves the session unlocked on success.
    /// Does not overwrite a vault that already exists.
    /// </summary>
    public void CreateVault(string masterPassword)
    {
        lock (_gate)
        {
            RequireLocked();
            // Repository validates the password and performs all KDF/key work.
            UnlockedVault vault = _repository.CreateNew(masterPassword);
            Activate(vault);
        }
    }

    /// <summary>
    /// Unlocks only after successful authenticated unwrap + index validation.
    /// Incorrect master passwords throw CryptographicException and remain locked.
    /// </summary>
    public void Unlock(string masterPassword)
    {
        lock (_gate)
        {
            RequireLocked();
            if (RemainingUnlockDelay() > TimeSpan.Zero)
                throw new InvalidOperationException("Unlock is temporarily unavailable.");

            try
            {
                UnlockedVault vault = _repository.Open(masterPassword);
                Activate(vault);
            }
            catch (Exception ex) when (ex is CryptographicException or ArgumentException)
            {
                // A too-short/invalid candidate is also a failed unlock. Do
                // not allow a distinct user-facing error for that condition.
                _failedUnlocks = Math.Min(_failedUnlocks + 1, 10);
                _lastFailure = _clock.GetTimestamp();
                throw new CryptographicException("Unable to unlock the vault.");
            }
        }
    }

    /// <summary>
    /// Releases the session's key material and the vault lock. Idempotent.
    /// No automatic save is required because successful mutations save first.
    /// </summary>
    public void Lock()
    {
        lock (_gate)
        {
            EnsureNotDisposed();
            if (_vault is not null)
                LockCore(VaultLockReason.Manual);
        }
    }

    public void SetInactivityTimeout(TimeSpan timeout)
    {
        ValidateTimeout(timeout);
        lock (_gate)
        {
            EnsureNotDisposed();
            _inactivityTimeout = timeout;
            ExpireIfIdle();
        }
    }

    /// <summary>
    /// Call only for real, meaningful user input while editing a form.
    /// Do not call from automatic UI refreshes or polling.
    /// </summary>
    public void RegisterUserActivity()
    {
        lock (_gate)
        {
            RequireUnlocked();
            MarkActivity();
        }
    }

    /// <summary>Lists only index metadata; passwords are not returned.</summary>
    public IReadOnlyList<VaultEntrySummary> ListEntries()
    {
        lock (_gate)
        {
            UnlockedVault vault = RequireUnlocked();
            IReadOnlyList<VaultEntrySummary> result = vault.ListEntries();
            MarkActivity();
            return result;
        }
    }

    /// <summary>
    /// Returns one plaintext credential to the caller. A later lock cannot
    /// erase immutable strings already returned; keep this object short-lived.
    /// Never log or display its Password property.
    /// </summary>
    public CredentialInput GetCredential(Guid id)
    {
        lock (_gate)
        {
            UnlockedVault vault = RequireUnlocked();
            try
            {
                CredentialInput result = vault.GetCredential(id);
                MarkActivity();
                return result;
            }
            catch (CryptographicException)
            {
                LockCore(VaultLockReason.IntegrityFailure);
                throw;
            }
            catch (InvalidDataException)
            {
                LockCore(VaultLockReason.IntegrityFailure);
                throw;
            }
        }
    }

    /// <summary>
    /// Adds and persists a credential before returning its ID. A save failure
    /// locks the session and leaves the previous on-disk vault intact.
    /// </summary>
    public Guid AddCredential(CredentialInput input)
    {
        lock (_gate)
        {
            UnlockedVault vault = RequireUnlocked();
            Guid id = vault.AddCredential(input);
            SaveOrLock(vault);
            MarkActivity();
            return id;
        }
    }

    public bool UpdateCredential(Guid id, CredentialInput input)
    {
        lock (_gate)
        {
            UnlockedVault vault = RequireUnlocked();
            if (!vault.UpdateCredential(id, input))
                return false;
            SaveOrLock(vault);
            MarkActivity();
            return true;
        }
    }

    public bool DeleteCredential(Guid id)
    {
        lock (_gate)
        {
            UnlockedVault vault = RequireUnlocked();
            if (!vault.DeleteCredential(id))
                return false;
            SaveOrLock(vault);
            MarkActivity();
            return true;
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            _timer?.Dispose();
            LockCore(VaultLockReason.Disposed);
        }
        GC.SuppressFinalize(this);
    }

    private void Activate(UnlockedVault vault)
    {
        _vault = vault;
        _lastLockReason = VaultLockReason.None;
        _failedUnlocks = 0;
        _lastFailure = 0;
        MarkActivity();
    }

    private void SaveOrLock(UnlockedVault vault)
    {
        try
        {
            vault.Save();
        }
        catch
        {
            // Do not leave dirty, uncommitted in-memory state accessible after
            // a failure. VaultFileStore.Write preserves the last valid file.
            try { LockCore(VaultLockReason.StorageFailure); }
            catch (Exception) { /* Preserve the original storage exception. */ }
            throw;
        }
    }

    private UnlockedVault RequireUnlocked()
    {
        EnsureNotDisposed();
        ExpireIfIdle();
        return _vault ?? throw new InvalidOperationException("The vault is locked.");
    }

    private void RequireLocked()
    {
        EnsureNotDisposed();
        ExpireIfIdle();
        if (_vault is not null)
            throw new InvalidOperationException("The vault is already unlocked.");
    }

    private void MarkActivity()
        => _lastActivity = _clock.GetTimestamp();

    private void ExpireIfIdle()
    {
        if (_vault is not null && _clock.GetElapsedTime(_lastActivity) >= _inactivityTimeout)
            LockCore(VaultLockReason.Inactivity);
    }

    private void LockCore(VaultLockReason reason)
    {
        UnlockedVault? vault = _vault;
        _vault = null; // Never expose an unlocked session after this point.
        _lastLockReason = reason;
        vault?.Dispose(); // Zeros the vault key and releases the exclusive lock.
    }

    private TimeSpan RemainingUnlockDelay()
    {
        // First failed attempt has no delay, then 1, 2, 4, 8 seconds maximum.
        if (_failedUnlocks < 2)
            return TimeSpan.Zero;
        int seconds = 1 << Math.Min(_failedUnlocks - 2, 3);
        TimeSpan elapsed = _clock.GetElapsedTime(_lastFailure);
        TimeSpan remaining = TimeSpan.FromSeconds(seconds) - elapsed;
        return remaining > TimeSpan.Zero ? remaining : TimeSpan.Zero;
    }

    private void OnTimer()
    {
        try
        {
            lock (_gate)
            {
                if (!_disposed)
                    ExpireIfIdle();
            }
        }
        catch (Exception)
        {
            // A callback exception must not terminate the application.
            // Make the session inaccessible even if disposing it fails.
            lock (_gate)
            {
                if (!_disposed && _vault is not null)
                {
                    try { LockCore(VaultLockReason.IntegrityFailure); }
                    catch (Exception) { _vault = null; }
                }
            }
        }
    }

    private void EnsureNotDisposed()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(VaultSessionManager));
    }

    private static void ValidateTimeout(TimeSpan timeout)
    {
        if (timeout <= TimeSpan.Zero || timeout > MaximumInactivityTimeout)
            throw new ArgumentOutOfRangeException(nameof(timeout),
                "The inactivity timeout must be positive and no greater than 24 hours.");
    }
}
