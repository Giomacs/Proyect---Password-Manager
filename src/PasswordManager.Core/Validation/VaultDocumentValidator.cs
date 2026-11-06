using PasswordManager.Core.Models;

namespace PasswordManager.Core.Validation;

/// <summary>
/// Structural validation of an UNTRUSTED vault document. This is not
/// authentication: AES-GCM tags and the authenticated index must also be
/// verified before the vault is unlocked (implemented in later stages).
/// </summary>
public static class VaultDocumentValidator
{
    public static ValidationResult ValidateFileSize(long byteLength)
    {
        var result = new ValidationResult();
        if (byteLength < 1 || byteLength > ValidationLimits.VaultFileMaxBytes)
            result.Add("vaultFile", "invalid_size");
        return result;
    }

    public static ValidationResult Validate(VaultFileDocument? vault)
    {
        var result = new ValidationResult();
        if (vault is null)
        {
            result.Add("vault", "required");
            return result;
        }

        if (vault.Magic != "SPM1") result.Add("magic", "unsupported_format");
        if (vault.FormatVersion != 1) result.Add("formatVersion", "unsupported_format");

        if (vault.Kdf is null)
        {
            result.Add("kdf", "required");
        }
        else
        {
            CheckBase64(result, "kdf.salt", vault.Kdf.Salt,
                ValidationLimits.SaltMinBytes, ValidationLimits.SaltMaxBytes);
            InRange(result, "kdf.memoryKiB", vault.Kdf.MemoryKiB,
                ValidationLimits.ArgonMemoryMinKiB, ValidationLimits.ArgonMemoryMaxKiB);
            InRange(result, "kdf.iterations", vault.Kdf.Iterations,
                ValidationLimits.ArgonIterationsMin, ValidationLimits.ArgonIterationsMax);
            InRange(result, "kdf.parallelism", vault.Kdf.Parallelism,
                ValidationLimits.ArgonParallelismMin, ValidationLimits.ArgonParallelismMax);
        }

        CheckBlob(result, "wrappedVaultKey", vault.WrappedVaultKey,
            ValidationLimits.VaultKeyBytes, ValidationLimits.VaultKeyBytes);
        CheckBlob(result, "index", vault.Index, 1, ValidationLimits.IndexCiphertextMaxBytes);

        if (vault.Records is null)
        {
            result.Add("records", "required");
        }
        else if (vault.Records.Count > ValidationLimits.VaultMaxRecords)
        {
            // Reject before visiting thousands of attacker-provided elements.
            result.Add("records", "too_many");
        }
        else
        {
            var ids = new HashSet<Guid>();
            foreach (var record in vault.Records)
            {
                if (record is null)
                {
                    result.Add("records", "invalid_record");
                    continue;
                }

                if (!Guid.TryParseExact(record.Id, "D", out Guid id) || id == Guid.Empty)
                    result.Add("records.id", "invalid_id");
                else if (!ids.Add(id))
                    result.Add("records.id", "duplicate_id");

                CheckBlob(result, "records", record,
                    1, ValidationLimits.RecordCiphertextMaxBytes);
            }
        }

        return result;
    }

    private static void InRange(ValidationResult result, string field, int value, int min, int max)
    {
        if (value < min || value > max)
            result.Add(field, "out_of_range");
    }

    private static void CheckBlob(
        ValidationResult result, string prefix, VaultEncryptedBlob? blob,
        int minCiphertextBytes, int maxCiphertextBytes)
    {
        if (blob is null)
        {
            result.Add(prefix, "required");
            return;
        }
        CheckBase64(result, prefix + ".nonce", blob.Nonce,
            ValidationLimits.GcmNonceBytes, ValidationLimits.GcmNonceBytes);
        CheckBase64(result, prefix + ".tag", blob.Tag,
            ValidationLimits.GcmTagBytes, ValidationLimits.GcmTagBytes);
        CheckBase64(result, prefix + ".ciphertext", blob.Ciphertext,
            minCiphertextBytes, maxCiphertextBytes);
    }

    private static void CheckBase64(
        ValidationResult result, string field, string? encoded, int minDecodedBytes,
        int maxDecodedBytes)
    {
        // Cap the encoded length before allocating a decoding buffer.
        int maxEncodedChars = ((maxDecodedBytes + 2) / 3) * 4;
        if (encoded is null || encoded.Length == 0 || encoded.Length > maxEncodedChars)
        {
            result.Add(field, "invalid_encoding_or_length");
            return;
        }
        try
        {
            byte[] decoded = Convert.FromBase64String(encoded);
            if (decoded.Length < minDecodedBytes || decoded.Length > maxDecodedBytes)
                result.Add(field, "invalid_encoding_or_length");
        }
        catch (FormatException)
        {
            result.Add(field, "invalid_encoding_or_length");
        }
    }
}
