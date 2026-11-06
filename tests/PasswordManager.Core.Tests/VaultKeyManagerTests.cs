using System.Security.Cryptography;
using PasswordManager.Core.Models;
using PasswordManager.Core.Security;
using PasswordManager.Core.Validation;
using Xunit;

namespace PasswordManager.Core.Tests;

public sealed class VaultKeyManagerTests
{
    private const string CorrectPassword = "Unit-Test-Master-Password-123";
    private const string WrongPassword = "Another-Unit-Test-Password-456";

    [Fact]
    public void GenerateVaultKey_ReturnsIndependentRandom256BitKeys()
    {
        byte[] one = VaultKeyManager.GenerateVaultKey();
        byte[] two = VaultKeyManager.GenerateVaultKey();
        try
        {
            Assert.Equal(32, one.Length);
            Assert.Equal(32, two.Length);
            Assert.False(one.SequenceEqual(two));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(one);
            CryptographicOperations.ZeroMemory(two);
        }
    }

    [Fact]
    public void CorrectPassword_UnwrapsOriginalVaultKey()
    {
        VaultKdfParameters p = Argon2idKeyDerivationTests.TestParameters();
        byte[] vaultKey = VaultKeyManager.GenerateVaultKey();
        byte[] unwrapped = Array.Empty<byte>();
        try
        {
            VaultEncryptedBlob wrapped = VaultKeyManager.WrapVaultKey(CorrectPassword, p, vaultKey);
            Assert.Equal(ValidationLimits.VaultKeyBytes,
                Convert.FromBase64String(wrapped.Ciphertext!).Length);
            unwrapped = VaultKeyManager.UnwrapVaultKey(CorrectPassword, p, wrapped);
            Assert.True(vaultKey.SequenceEqual(unwrapped));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(vaultKey);
            CryptographicOperations.ZeroMemory(unwrapped);
        }
    }

    [Fact]
    public void WrongPassword_DoesNotUnwrapVaultKey()
    {
        VaultKdfParameters p = Argon2idKeyDerivationTests.TestParameters();
        byte[] vaultKey = VaultKeyManager.GenerateVaultKey();
        try
        {
            VaultEncryptedBlob wrapped = VaultKeyManager.WrapVaultKey(CorrectPassword, p, vaultKey);
            Assert.Throws<CryptographicException>(() =>
                VaultKeyManager.UnwrapVaultKey(WrongPassword, p, wrapped));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(vaultKey);
        }
    }

    [Fact]
    public void ModifiedWrappedKey_IsRejected()
    {
        VaultKdfParameters p = Argon2idKeyDerivationTests.TestParameters();
        byte[] vaultKey = VaultKeyManager.GenerateVaultKey();
        try
        {
            VaultEncryptedBlob wrapped = VaultKeyManager.WrapVaultKey(CorrectPassword, p, vaultKey);
            byte[] tag = Convert.FromBase64String(wrapped.Tag!);
            tag[0] ^= 0x80;
            wrapped.Tag = Convert.ToBase64String(tag);
            Assert.Throws<CryptographicException>(() =>
                VaultKeyManager.UnwrapVaultKey(CorrectPassword, p, wrapped));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(vaultKey);
        }
    }
}
