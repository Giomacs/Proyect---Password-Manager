using System.Security.Cryptography;
using System.Text;
using PasswordManager.Core.Models;
using PasswordManager.Core.Security;
using PasswordManager.Core.Validation;
using Xunit;

namespace PasswordManager.Core.Tests;

public sealed class VaultAesGcmTests
{
    [Fact]
    public void EncryptDecryptRecord_RoundTripsBytesAndBindsRecordId()
    {
        byte[] key = VaultKeyManager.GenerateVaultKey();
        byte[] plaintext = Encoding.UTF8.GetBytes("{\"password\":\"synthetic-test-only\"}");
        Guid id = Guid.NewGuid();
        byte[] recovered = Array.Empty<byte>();

        try
        {
            VaultEncryptedRecord record = VaultAesGcm.EncryptRecord(key, id, plaintext);
            Assert.Equal(id.ToString("D"), record.Id);
            Assert.NotEqual(Convert.ToBase64String(plaintext), record.Ciphertext);
            Assert.Equal(12, Convert.FromBase64String(record.Nonce!).Length);
            Assert.Equal(16, Convert.FromBase64String(record.Tag!).Length);

            recovered = VaultAesGcm.DecryptRecord(key, record);
            Assert.True(plaintext.SequenceEqual(recovered));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(recovered);
        }
    }

    [Fact]
    public void TamperedCiphertextOrTag_IsRejected()
    {
        byte[] key = VaultKeyManager.GenerateVaultKey();
        try
        {
            VaultEncryptedRecord record = VaultAesGcm.EncryptRecord(
                key, Guid.NewGuid(), Encoding.UTF8.GetBytes("synthetic entry"));

            byte[] ciphertext = Convert.FromBase64String(record.Ciphertext!);
            ciphertext[0] ^= 0x01;
            var wrongCiphertext = new VaultEncryptedRecord
            {
                Id = record.Id, Nonce = record.Nonce,
                Tag = record.Tag, Ciphertext = Convert.ToBase64String(ciphertext)
            };
            Assert.Throws<CryptographicException>(() => VaultAesGcm.DecryptRecord(key, wrongCiphertext));

            byte[] tag = Convert.FromBase64String(record.Tag!);
            tag[0] ^= 0x01;
            var wrongTag = new VaultEncryptedRecord
            {
                Id = record.Id, Nonce = record.Nonce,
                Tag = Convert.ToBase64String(tag), Ciphertext = record.Ciphertext
            };
            Assert.Throws<CryptographicException>(() => VaultAesGcm.DecryptRecord(key, wrongTag));

            byte[] nonce = Convert.FromBase64String(record.Nonce!);
            nonce[0] ^= 0x01;
            var wrongNonce = new VaultEncryptedRecord
            {
                Id = record.Id, Nonce = Convert.ToBase64String(nonce),
                Tag = record.Tag, Ciphertext = record.Ciphertext
            };
            Assert.Throws<CryptographicException>(() => VaultAesGcm.DecryptRecord(key, wrongNonce));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    [Fact]
    public void ChangingRecordId_CausesAuthenticationFailure()
    {
        byte[] key = VaultKeyManager.GenerateVaultKey();
        try
        {
            VaultEncryptedRecord record = VaultAesGcm.EncryptRecord(
                key, Guid.NewGuid(), Encoding.UTF8.GetBytes("synthetic credential"));
            record.Id = Guid.NewGuid().ToString("D");
            Assert.Throws<CryptographicException>(() => VaultAesGcm.DecryptRecord(key, record));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    [Fact]
    public void IndexAndRecordUseDifferentAuthenticatedContexts()
    {
        byte[] key = VaultKeyManager.GenerateVaultKey();
        byte[] recovered = Array.Empty<byte>();
        byte[] plaintext = Encoding.UTF8.GetBytes("{\"entries\":[]}");
        try
        {
            VaultEncryptedBlob encryptedIndex = VaultAesGcm.EncryptIndex(key, plaintext);
            recovered = VaultAesGcm.DecryptIndex(key, encryptedIndex);
            Assert.True(plaintext.SequenceEqual(recovered));

            var sameBlobPretendingToBeRecord = new VaultEncryptedRecord
            {
                Id = Guid.NewGuid().ToString("D"), Nonce = encryptedIndex.Nonce,
                Tag = encryptedIndex.Tag, Ciphertext = encryptedIndex.Ciphertext
            };
            Assert.Throws<CryptographicException>(() =>
                VaultAesGcm.DecryptRecord(key, sameBlobPretendingToBeRecord));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(recovered);
        }
    }

    [Fact]
    public void EncryptSamePlaintextTwice_UsesFreshNonces()
    {
        byte[] key = VaultKeyManager.GenerateVaultKey();
        try
        {
            byte[] plaintext = Encoding.UTF8.GetBytes("[1]");
            VaultEncryptedBlob a = VaultAesGcm.EncryptIndex(key, plaintext);
            VaultEncryptedBlob b = VaultAesGcm.EncryptIndex(key, plaintext);
            Assert.NotEqual(a.Nonce, b.Nonce);
            Assert.NotEqual(a.Ciphertext, b.Ciphertext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    [Fact]
    public void IncorrectKey_IsRejected()
    {
        byte[] key = VaultKeyManager.GenerateVaultKey();
        byte[] other = VaultKeyManager.GenerateVaultKey();
        try
        {
            VaultEncryptedBlob data = VaultAesGcm.EncryptIndex(
                key, Encoding.UTF8.GetBytes("synthetic"));
            Assert.Throws<CryptographicException>(() => VaultAesGcm.DecryptIndex(other, data));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(other);
        }
    }

    [Fact]
    public void InvalidBlobAndOversizedInput_AreRejected()
    {
        byte[] key = VaultKeyManager.GenerateVaultKey();
        try
        {
            Assert.Throws<ArgumentException>(() => VaultAesGcm.EncryptIndex(key, Array.Empty<byte>()));
            Assert.Throws<ArgumentException>(() => VaultAesGcm.EncryptRecord(
                key, Guid.Empty, Encoding.UTF8.GetBytes("data")));
            Assert.Throws<ArgumentException>(() => VaultAesGcm.DecryptIndex(key, new VaultEncryptedBlob
            {
                Nonce = Convert.ToBase64String(new byte[12]),
                Tag = Convert.ToBase64String(new byte[16]),
                Ciphertext = new string('A', ValidationLimits.IndexCiphertextMaxBytes * 4)
            }));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }
}
