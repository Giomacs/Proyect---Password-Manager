using System.Security.Cryptography;
using System.Text;
using PasswordManager.Core.Models;
using PasswordManager.Core.Validation;

namespace PasswordManager.Core.Security;

/// <summary>
/// Authenticated AES-256-GCM operations. AAD separates the key-wrap,
/// encrypted index, and individual record contexts.
/// Decrypted byte arrays are sensitive and must be cleared by callers.
/// </summary>
public static class VaultAesGcm
{
    private static readonly byte[] KeyWrapAad = Encoding.ASCII.GetBytes("SPM/v1/key-wrap");
    private static readonly byte[] IndexAad = Encoding.ASCII.GetBytes("SPM/v1/index");

    public static VaultEncryptedBlob EncryptIndex(ReadOnlySpan<byte> vaultKey, ReadOnlySpan<byte> plaintext)
    {
        CheckLength(plaintext.Length, ValidationLimits.IndexCiphertextMaxBytes);
        return Encrypt(vaultKey, plaintext, IndexAad);
    }

    public static byte[] DecryptIndex(ReadOnlySpan<byte> vaultKey, VaultEncryptedBlob? blob)
        => Decrypt(vaultKey, blob, IndexAad, ValidationLimits.IndexCiphertextMaxBytes);

    public static VaultEncryptedRecord EncryptRecord(
        ReadOnlySpan<byte> vaultKey, Guid recordId, ReadOnlySpan<byte> plaintext)
    {
        CheckRecordId(recordId);
        CheckLength(plaintext.Length, ValidationLimits.RecordCiphertextMaxBytes);
        byte[] aad = RecordAad(recordId);
        VaultEncryptedBlob encrypted = Encrypt(vaultKey, plaintext, aad);
        return new VaultEncryptedRecord
        {
            Id = recordId.ToString("D"),
            Nonce = encrypted.Nonce,
            Ciphertext = encrypted.Ciphertext,
            Tag = encrypted.Tag
        };
    }

    public static byte[] DecryptRecord(ReadOnlySpan<byte> vaultKey, VaultEncryptedRecord? record)
    {
        if (record is null || !Guid.TryParseExact(record.Id, "D", out Guid id) || id == Guid.Empty)
            throw new ArgumentException("Invalid encrypted record.", nameof(record));

        return Decrypt(vaultKey, record, RecordAad(id), ValidationLimits.RecordCiphertextMaxBytes);
    }

    internal static VaultEncryptedBlob EncryptWrappedKey(
        ReadOnlySpan<byte> kek, ReadOnlySpan<byte> vaultKey)
    {
        if (vaultKey.Length != ValidationLimits.VaultKeyBytes)
            throw new ArgumentException("Invalid vault key length.", nameof(vaultKey));
        return Encrypt(kek, vaultKey, KeyWrapAad);
    }

    internal static byte[] DecryptWrappedKey(ReadOnlySpan<byte> kek, VaultEncryptedBlob? blob)
    {
        byte[] unwrapped = Decrypt(kek, blob, KeyWrapAad, ValidationLimits.VaultKeyBytes);
        if (unwrapped.Length == ValidationLimits.VaultKeyBytes)
            return unwrapped;

        CryptographicOperations.ZeroMemory(unwrapped);
        throw new CryptographicException("Vault authentication failed.");
    }

    private static VaultEncryptedBlob Encrypt(
        ReadOnlySpan<byte> key, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> aad)
    {
        CheckKey(key);
        byte[] nonce = RandomNumberGenerator.GetBytes(ValidationLimits.GcmNonceBytes);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[ValidationLimits.GcmTagBytes];

        try
        {
            using var aes = new AesGcm(key, ValidationLimits.GcmTagBytes);
            aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);
            return new VaultEncryptedBlob
            {
                Nonce = Convert.ToBase64String(nonce),
                Ciphertext = Convert.ToBase64String(ciphertext),
                Tag = Convert.ToBase64String(tag)
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
            CryptographicOperations.ZeroMemory(nonce);
        }
    }

    private static byte[] Decrypt(
        ReadOnlySpan<byte> key, VaultEncryptedBlob? blob,
        ReadOnlySpan<byte> aad, int maxCiphertextBytes)
    {
        CheckKey(key);
        if (blob is null)
            throw new ArgumentException("Invalid encrypted data.", nameof(blob));

        byte[] nonce = DecodeExact(blob.Nonce, ValidationLimits.GcmNonceBytes);
        byte[] tag = Array.Empty<byte>();
        byte[] ciphertext = Array.Empty<byte>();
        byte[] plaintext = Array.Empty<byte>();
        bool success = false;

        try
        {
            tag = DecodeExact(blob.Tag, ValidationLimits.GcmTagBytes);
            ciphertext = DecodeBounded(blob.Ciphertext, maxCiphertextBytes);
            plaintext = new byte[ciphertext.Length];

            using var aes = new AesGcm(key, ValidationLimits.GcmTagBytes);
            try
            {
                aes.Decrypt(nonce, ciphertext, tag, plaintext, aad);
            }
            catch (CryptographicException)
            {
                throw new CryptographicException("Encrypted data authentication failed.");
            }

            success = true;
            return plaintext;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(tag);
            CryptographicOperations.ZeroMemory(ciphertext);
            if (!success)
                CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private static byte[] DecodeExact(string? encoded, int size)
    {
        byte[] decoded = DecodeBounded(encoded, size);
        if (decoded.Length == size) return decoded;
        CryptographicOperations.ZeroMemory(decoded);
        throw new ArgumentException("Invalid encrypted data encoding.");
    }

    private static byte[] DecodeBounded(string? encoded, int maxBytes)
    {
        int maxEncodedChars = checked(((maxBytes + 2) / 3) * 4);
        if (encoded is null || encoded.Length == 0 || encoded.Length > maxEncodedChars)
            throw new ArgumentException("Invalid encrypted data encoding.");

        try
        {
            byte[] decoded = Convert.FromBase64String(encoded);
            if (decoded.Length > 0 && decoded.Length <= maxBytes)
                return decoded;

            CryptographicOperations.ZeroMemory(decoded);
            throw new ArgumentException("Invalid encrypted data length.");
        }
        catch (FormatException)
        {
            throw new ArgumentException("Invalid encrypted data encoding.");
        }
    }

    private static byte[] RecordAad(Guid recordId)
        => Encoding.ASCII.GetBytes("SPM/v1/record/" + recordId.ToString("D"));

    private static void CheckKey(ReadOnlySpan<byte> key)
    {
        if (key.Length != ValidationLimits.VaultKeyBytes)
            throw new ArgumentException("A 256-bit key is required.", nameof(key));
    }

    private static void CheckRecordId(Guid recordId)
    {
        if (recordId == Guid.Empty)
            throw new ArgumentException("Record ID must not be empty.", nameof(recordId));
    }

    private static void CheckLength(int length, int max)
    {
        if (length <= 0 || length > max)
            throw new ArgumentException("Invalid plaintext length.");
    }
}
