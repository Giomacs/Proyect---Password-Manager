using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PasswordManager.Core.Models;
using PasswordManager.Core.Storage;
using Xunit;

namespace PasswordManager.Core.Tests;

public sealed class VaultTamperingTests
{
    private const string Master = "A-Valid-Master-Password-for-Tests";

    [Theory]
    [InlineData("record-byte")]
    [InlineData("record-delete")]
    [InlineData("record-id")]
    [InlineData("index-tag")]
    [InlineData("wrap-tag")]
    [InlineData("wrap-nonce")]
    public void TamperedVault_FailsBeforeUnlock(string modification)
    {
        using var temp = new TemporaryVaultDirectory();
        var repo = new VaultRepository(temp.Path);
        using (var vault = repo.CreateNewWithParameters(
            Master, Argon2idKeyDerivationTests.TestParameters()))
        {
            vault.AddCredential(new CredentialInput
            {
                Title = "Entry", Username = "tester", Password = "Example secret"
            });
            vault.Save();
        }

        VaultFileDocument doc = ReadDocument(temp.VaultFile);
        switch (modification)
        {
            case "record-byte":
                doc.Records![0].Ciphertext = FlipFirstDecodedByte(doc.Records[0].Ciphertext!);
                break;
            case "record-delete":
                doc.Records!.Clear();
                break;
            case "record-id":
                doc.Records![0].Id = Guid.NewGuid().ToString("D");
                break;
            case "index-tag":
                doc.Index!.Tag = FlipFirstDecodedByte(doc.Index.Tag!);
                break;
            case "wrap-tag":
                doc.WrappedVaultKey!.Tag = FlipFirstDecodedByte(doc.WrappedVaultKey.Tag!);
                break;
            case "wrap-nonce":
                doc.WrappedVaultKey!.Nonce = FlipFirstDecodedByte(doc.WrappedVaultKey.Nonce!);
                break;
        }
        File.WriteAllText(temp.VaultFile, JsonSerializer.Serialize(doc));
        if (modification is "index-tag" or "wrap-tag" or "wrap-nonce")
            Assert.Throws<CryptographicException>(() => repo.Open(Master));
        else
            Assert.Throws<InvalidDataException>(() => repo.Open(Master));
    }

    [Fact]
    public void MaliciousKdfMemory_IsRejectedBeforeArgon2()
    {
        using var temp = new TemporaryVaultDirectory();
        var repo = new VaultRepository(temp.Path);
        using (repo.CreateNewWithParameters(
            Master, Argon2idKeyDerivationTests.TestParameters())) { }
        VaultFileDocument doc = ReadDocument(temp.VaultFile);
        doc.Kdf!.MemoryKiB = int.MaxValue;
        File.WriteAllText(temp.VaultFile, JsonSerializer.Serialize(doc));
        Assert.Throws<InvalidDataException>(() => repo.Open(Master));
    }

    [Fact]
    public void DuplicateJsonProperties_AreRejected()
    {
        using var temp = new TemporaryVaultDirectory();
        var repo = new VaultRepository(temp.Path);
        using (repo.CreateNewWithParameters(
            Master, Argon2idKeyDerivationTests.TestParameters())) { }
        string json = File.ReadAllText(temp.VaultFile);
        // The field name deliberately appears twice with different values.
        json = json.Replace("\"magic\":\"SPM1\"",
            "\"magic\":\"SPM1\",\"magic\":\"SPM1\"", StringComparison.Ordinal);
        File.WriteAllText(temp.VaultFile, json);
        Assert.Throws<InvalidDataException>(() => repo.Open(Master));
    }

    [Fact]
    public void MissingOrMalformedFile_IsRejected()
    {
        using var temp = new TemporaryVaultDirectory();
        var repo = new VaultRepository(temp.Path);
        Assert.Throws<FileNotFoundException>(() => repo.Open(Master));

        Directory.CreateDirectory(temp.Path);
        File.WriteAllText(temp.VaultFile, "{not valid JSON");
        Assert.Throws<InvalidDataException>(() => repo.Open(Master));
    }

    [Fact]
    public void OversizedVaultFile_IsRejected()
    {
        using var temp = new TemporaryVaultDirectory();
        var repo = new VaultRepository(temp.Path);
        Directory.CreateDirectory(temp.Path);
        using (var file = new FileStream(temp.VaultFile, FileMode.CreateNew,
            FileAccess.Write, FileShare.None))
        {
            file.SetLength(8L * 1024 * 1024 + 1);
        }
        Assert.Throws<InvalidDataException>(() => repo.Open(Master));
    }

    private static VaultFileDocument ReadDocument(string path)
        => JsonSerializer.Deserialize<VaultFileDocument>(File.ReadAllText(path))!;

    private static string FlipFirstDecodedByte(string base64)
    {
        byte[] bytes = Convert.FromBase64String(base64);
        bytes[0] ^= 0x01;
        return Convert.ToBase64String(bytes);
    }

    private sealed class TemporaryVaultDirectory : IDisposable
    {
        public string Path { get; } = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(), "SPM-Stage3-Tamper-" + Guid.NewGuid().ToString("N"));
        public string VaultFile => System.IO.Path.Combine(Path, "vault.spm");
        public void Dispose()
        {
            if (Directory.Exists(Path)) Directory.Delete(Path, recursive: true);
        }
    }
}
