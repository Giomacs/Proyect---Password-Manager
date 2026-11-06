namespace PasswordManager.Core.Validation;

/// <summary>Maximums are deliberately conservative for a single-user vault.</summary>
public static class ValidationLimits
{
    public const int MasterPasswordMinChars = 12;
    public const int MasterPasswordMaxChars = 1024;

    public const int TitleMaxChars = 128;
    public const int UsernameMaxChars = 256;
    public const int CredentialPasswordMaxChars = 4096;
    public const int UrlMaxChars = 2048;
    public const int NotesMaxChars = 16384;

    public const long VaultFileMaxBytes = 8L * 1024 * 1024;
    public const int VaultMaxRecords = 1024;
    public const int RecordCiphertextMaxBytes = 128 * 1024;
    public const int IndexCiphertextMaxBytes = 256 * 1024;

    public const int ArgonMemoryMinKiB = 32 * 1024;
    public const int ArgonMemoryMaxKiB = 256 * 1024;
    public const int ArgonIterationsMin = 1;
    public const int ArgonIterationsMax = 8;
    public const int ArgonParallelismMin = 1;
    public const int ArgonParallelismMax = 4;

    public const int SaltMinBytes = 16;
    public const int SaltMaxBytes = 32;
    public const int GcmNonceBytes = 12;
    public const int GcmTagBytes = 16;
    public const int VaultKeyBytes = 32;
}
