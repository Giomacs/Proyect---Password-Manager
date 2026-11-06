using PasswordManager.Core.Models;
using PasswordManager.Core.Validation;

namespace PasswordManager.Core.Tests;

public sealed class VaultDocumentValidatorTests
{
    private static string B64(int bytes) => Convert.ToBase64String(new byte[bytes]);

    private static VaultFileDocument ValidVault() => new()
    {
        Magic = "SPM1",
        FormatVersion = 1,
        Kdf = new VaultKdfParameters
        {
            Salt = B64(16),
            MemoryKiB = 65536,
            Iterations = 3,
            Parallelism = 1
        },
        WrappedVaultKey = new VaultEncryptedBlob
        {
            Nonce = B64(12), Ciphertext = B64(32), Tag = B64(16)
        },
        Index = new VaultEncryptedBlob
        {
            Nonce = B64(12), Ciphertext = B64(16), Tag = B64(16)
        },
        Records = new List<VaultEncryptedRecord>()
    };

    [Fact]
    public void ValidStructurePasses()
    {
        Assert.True(VaultDocumentValidator.Validate(ValidVault()).IsValid);
    }

    [Fact]
    public void RejectsUnsupportedFormat()
    {
        var vault = ValidVault();
        vault.FormatVersion = 999;
        Assert.Contains(VaultDocumentValidator.Validate(vault).Issues,
            e => e.Field == "formatVersion" && e.Code == "unsupported_format");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(999999999)]
    public void RejectsUnboundedArgonMemory(int memoryKiB)
    {
        var vault = ValidVault();
        vault.Kdf!.MemoryKiB = memoryKiB;
        Assert.Contains(VaultDocumentValidator.Validate(vault).Issues,
            e => e.Field == "kdf.memoryKiB" && e.Code == "out_of_range");
    }

    [Fact]
    public void RejectsBadNonceLength()
    {
        var vault = ValidVault();
        vault.Index!.Nonce = B64(11);
        Assert.Contains(VaultDocumentValidator.Validate(vault).Issues,
            e => e.Field == "index.nonce");
    }

    [Fact]
    public void RejectsInvalidBase64AndTagLength()
    {
        var vault = ValidVault();
        vault.WrappedVaultKey!.Ciphertext = "not base64!";
        vault.WrappedVaultKey.Tag = B64(15);
        var result = VaultDocumentValidator.Validate(vault);
        Assert.Contains(result.Issues, e => e.Field == "wrappedVaultKey.ciphertext");
        Assert.Contains(result.Issues, e => e.Field == "wrappedVaultKey.tag");
    }

    [Fact]
    public void RejectsDuplicateRecordIds()
    {
        var vault = ValidVault();
        string id = Guid.NewGuid().ToString("D");
        vault.Records!.Add(new VaultEncryptedRecord
        {
            Id = id, Nonce = B64(12), Ciphertext = B64(1), Tag = B64(16)
        });
        vault.Records.Add(new VaultEncryptedRecord
        {
            Id = id.ToUpperInvariant(), Nonce = B64(12), Ciphertext = B64(1), Tag = B64(16)
        });

        Assert.Contains(VaultDocumentValidator.Validate(vault).Issues,
            e => e.Field == "records.id" && e.Code == "duplicate_id");
    }

    [Fact]
    public void RejectsTooManyRecords()
    {
        var vault = ValidVault();
        vault.Records = Enumerable.Repeat(
            new VaultEncryptedRecord(), ValidationLimits.VaultMaxRecords + 1).ToList();
        Assert.Contains(VaultDocumentValidator.Validate(vault).Issues,
            e => e.Field == "records" && e.Code == "too_many");
    }

    [Fact]
    public void RejectsOversizedEncodedCiphertext()
    {
        var vault = ValidVault();
        vault.Index!.Ciphertext = new string('A', 400000);
        Assert.Contains(VaultDocumentValidator.Validate(vault).Issues,
            e => e.Field == "index.ciphertext");
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(9000000)]
    public void RejectsInvalidFileSize(long fileBytes)
    {
        Assert.False(VaultDocumentValidator.ValidateFileSize(fileBytes).IsValid);
    }
}
