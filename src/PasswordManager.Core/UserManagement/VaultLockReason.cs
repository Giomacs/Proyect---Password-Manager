namespace PasswordManager.Core.UserManagement;

/// <summary>Reason the most recent unlocked session ended.</summary>
public enum VaultLockReason
{
    None,
    Manual,
    Inactivity,
    StorageFailure,
    IntegrityFailure,
    Disposed
}
