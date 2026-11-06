using System.Security.Cryptography;
using PasswordManager.Core.Models;
using PasswordManager.Core.Validation;

namespace PasswordManager.Core.Security;

/// <summary>
/// Creates and protects the independent vault encryption key.
/// Callers own returned key arrays and must erase them when locking.
/// </summary>
public static class VaultKeyManager
{
    public static byte[] GenerateVaultKey()
        => RandomNumberGenerator.GetBytes(ValidationLimits.VaultKeyBytes);

    public static VaultEncryptedBlob WrapVaultKey(
        string masterPassword, VaultKdfParameters parameters, ReadOnlySpan<byte> vaultKey)
    {
        if (vaultKey.Length != ValidationLimits.VaultKeyBytes)
            throw new ArgumentException("Invalid vault key length.", nameof(vaultKey));

        byte[] kek = Argon2idKeyDerivation.DeriveKek(masterPassword, parameters);
        try
        {
            return VaultAesGcm.EncryptWrappedKey(kek, vaultKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    /// <summary>
    /// A wrong master password and a modified key-wrap authentication tag
    /// both fail with CryptographicException. A successful call returns
    /// the raw 32-byte vault key; the caller must securely clear it.
    /// </summary>
    public static byte[] UnwrapVaultKey(
        string masterPassword, VaultKdfParameters parameters, VaultEncryptedBlob? wrappedVaultKey)
    {
        byte[] kek = Argon2idKeyDerivation.DeriveKek(masterPassword, parameters);
        try
        {
            return VaultAesGcm.DecryptWrappedKey(kek, wrappedVaultKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
    }
}
