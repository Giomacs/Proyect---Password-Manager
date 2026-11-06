using System.Security.Cryptography;
using PasswordManager.Core.Models;
using PasswordManager.Core.Security;
using PasswordManager.Core.Validation;

namespace PasswordManager.Core.Storage;

/// <summary>
/// Entry point for creating or reopening the single offline vault.
/// Session lifetime and auto-lock policies will be added in Section 4.
/// </summary>
public sealed class VaultRepository
{
    private readonly VaultFileStore _store;

    public VaultRepository() : this(new VaultFileStore()) { }

    // Isolated test directory only, not available to the WPF application.
    internal VaultRepository(string testDirectory) : this(new VaultFileStore(testDirectory)) { }

    private VaultRepository(VaultFileStore store) => _store = store;

    public bool VaultExists => _store.Exists;

    public UnlockedVault CreateNew(string masterPassword)
        => CreateNewWithParameters(masterPassword, Argon2idKeyDerivation.CreateParameters());

    // Internal test-only path permits the least expensive policy-approved KDF settings.
    internal UnlockedVault CreateNewWithParameters(
        string masterPassword, VaultKdfParameters parameters)
    {
        if (!CredentialValidator.ValidateMasterPassword(masterPassword).IsValid)
            throw new ArgumentException("Invalid master password.", nameof(masterPassword));

        FileStream? heldLock = null;
        byte[] vaultKey = Array.Empty<byte>();
        try
        {
            heldLock = _store.AcquireLock();
            vaultKey = VaultKeyManager.GenerateVaultKey();
            Argon2idKeyDerivation.ValidateParameters(parameters);
            VaultEncryptedBlob wrapped = VaultKeyManager.WrapVaultKey(masterPassword, parameters, vaultKey);

            var index = new VaultIndexDocument();
            VaultEncryptedBlob encryptedIndex = UnlockedVault.EncryptIndex(vaultKey, index);
            var document = new VaultFileDocument
            {
                Magic = "SPM1",
                FormatVersion = 1,
                Kdf = parameters,
                WrappedVaultKey = wrapped,
                Index = encryptedIndex,
                Records = new List<VaultEncryptedRecord>()
            };

            _store.Write(document, createOnly: true);
            var opened = new UnlockedVault(_store, heldLock, vaultKey, document, index);
            heldLock = null;
            vaultKey = Array.Empty<byte>();
            return opened;
        }
        finally
        {
            heldLock?.Dispose();
            CryptographicOperations.ZeroMemory(vaultKey);
        }
    }

    public UnlockedVault Open(string masterPassword)
    {
        if (!CredentialValidator.ValidateMasterPassword(masterPassword).IsValid)
            throw new ArgumentException("Invalid master password.", nameof(masterPassword));

        FileStream? heldLock = null;
        byte[] vaultKey = Array.Empty<byte>();
        try
        {
            heldLock = _store.AcquireLock();
            VaultFileDocument document = _store.Read();
            vaultKey = VaultKeyManager.UnwrapVaultKey(
                masterPassword, document.Kdf!, document.WrappedVaultKey);

            VaultIndexDocument index = UnlockedVault.DecryptIndex(vaultKey, document.Index);
            UnlockedVault.VerifyIndex(index, document.Records!);

            var opened = new UnlockedVault(_store, heldLock, vaultKey, document, index);
            heldLock = null;
            vaultKey = Array.Empty<byte>();
            return opened;
        }
        finally
        {
            heldLock?.Dispose();
            CryptographicOperations.ZeroMemory(vaultKey);
        }
    }
}
