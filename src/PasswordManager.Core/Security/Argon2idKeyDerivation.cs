using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
using PasswordManager.Core.Models;
using PasswordManager.Core.Validation;

namespace PasswordManager.Core.Security;

/// <summary>
/// Derives a 256-bit key-encryption key from the master password.
/// The master password is not itself an AES key and is never persisted.
/// The returned key is sensitive: its caller must clear it after use.
/// </summary>
public static class Argon2idKeyDerivation
{
    private const int DefaultMemoryKiB = 64 * 1024;
    private const int DefaultIterations = 3;
    private const int DefaultParallelism = 1;
    private const int SaltBytes = 16;

    private static readonly Encoding StrictUtf8 = new UTF8Encoding(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    /// <summary>Creates fresh public KDF metadata for a new vault.</summary>
    public static VaultKdfParameters CreateParameters()
    {
        return new VaultKdfParameters
        {
            Salt = Convert.ToBase64String(RandomNumberGenerator.GetBytes(SaltBytes)),
            MemoryKiB = DefaultMemoryKiB,
            Iterations = DefaultIterations,
            Parallelism = DefaultParallelism
        };
    }

    /// <summary>
    /// Argon2id(masterPassword, validated parameters) -> a 32-byte KEK.
    /// No trimming or Unicode normalization is performed on the password.
    /// </summary>
    public static byte[] DeriveKek(string? masterPassword, VaultKdfParameters? parameters)
    {
        if (!CredentialValidator.ValidateMasterPassword(masterPassword).IsValid)
            throw new ArgumentException("Invalid master password.", nameof(masterPassword));

        ValidateParameters(parameters);

        // CreateParameters/ValidateParameters ensure this is exactly 16..32 bytes.
        byte[] salt = Convert.FromBase64String(parameters!.Salt!);
        byte[] passwordBytes = Array.Empty<byte>();

        try
        {
            passwordBytes = StrictUtf8.GetBytes(masterPassword!);
            using var argon2 = new Argon2id(passwordBytes)
            {
                Salt = salt,
                MemorySize = parameters.MemoryKiB,
                Iterations = parameters.Iterations,
                DegreeOfParallelism = parameters.Parallelism
            };

            return argon2.GetBytes(ValidationLimits.VaultKeyBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
            CryptographicOperations.ZeroMemory(salt);
        }
    }

    /// <summary>
    /// Rejects attacker-controlled parameters before expensive KDF work.
    /// Does not accept arbitrary algorithm choices or unbounded settings.
    /// </summary>
    public static void ValidateParameters(VaultKdfParameters? parameters)
    {
        if (parameters is null ||
            parameters.MemoryKiB < ValidationLimits.ArgonMemoryMinKiB ||
            parameters.MemoryKiB > ValidationLimits.ArgonMemoryMaxKiB ||
            parameters.Iterations < ValidationLimits.ArgonIterationsMin ||
            parameters.Iterations > ValidationLimits.ArgonIterationsMax ||
            parameters.Parallelism < ValidationLimits.ArgonParallelismMin ||
            parameters.Parallelism > ValidationLimits.ArgonParallelismMax ||
            !ValidSalt(parameters.Salt))
        {
            throw new ArgumentException("Invalid key-derivation parameters.", nameof(parameters));
        }
    }

    private static bool ValidSalt(string? encoded)
    {
        if (encoded is null)
            return false;

        // 32 bytes needs 44 Base64 characters; reject before allocating.
        int maxChars = ((ValidationLimits.SaltMaxBytes + 2) / 3) * 4;
        if (encoded.Length == 0 || encoded.Length > maxChars)
            return false;

        Span<byte> decoded = stackalloc byte[ValidationLimits.SaltMaxBytes];
        try
        {
            return Convert.TryFromBase64String(encoded, decoded, out int written) &&
                   written >= ValidationLimits.SaltMinBytes &&
                   written <= ValidationLimits.SaltMaxBytes;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(decoded);
        }
    }
}
