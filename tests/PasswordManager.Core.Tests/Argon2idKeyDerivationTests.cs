using System.Security.Cryptography;
using PasswordManager.Core.Models;
using PasswordManager.Core.Security;
using PasswordManager.Core.Validation;
using Xunit;

namespace PasswordManager.Core.Tests;

public sealed class Argon2idKeyDerivationTests
{
    private const string TestMasterPassword = "Unit-Test-Master-Password-123";

    [Fact]
    public void CreateParameters_UsesRandomSaltAndConfiguredBounds()
    {
        VaultKdfParameters first = Argon2idKeyDerivation.CreateParameters();
        VaultKdfParameters second = Argon2idKeyDerivation.CreateParameters();

        Assert.NotEqual(first.Salt, second.Salt);
        Assert.Equal(16, Convert.FromBase64String(first.Salt!).Length);
        Assert.Equal(64 * 1024, first.MemoryKiB);
        Assert.Equal(3, first.Iterations);
        Assert.Equal(1, first.Parallelism);
        Argon2idKeyDerivation.ValidateParameters(first);
    }

    [Fact]
    public void DeriveKek_SamePasswordAndParametersGivesSameKey()
    {
        VaultKdfParameters p = TestParameters();
        byte[] first = Argon2idKeyDerivation.DeriveKek(TestMasterPassword, p);
        byte[] second = Argon2idKeyDerivation.DeriveKek(TestMasterPassword, p);
        try
        {
            Assert.Equal(ValidationLimits.VaultKeyBytes, first.Length);
            Assert.True(first.SequenceEqual(second));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(first);
            CryptographicOperations.ZeroMemory(second);
        }
    }

    [Theory]
    [InlineData(0, 1, 1)]
    [InlineData(262145, 1, 1)]
    [InlineData(32768, 0, 1)]
    [InlineData(32768, 9, 1)]
    [InlineData(32768, 1, 0)]
    [InlineData(32768, 1, 5)]
    public void DeriveKek_RejectsUnboundedParametersBeforeKdfWork(
        int memoryKiB, int iterations, int parallelism)
    {
        VaultKdfParameters p = TestParameters();
        p.MemoryKiB = memoryKiB;
        p.Iterations = iterations;
        p.Parallelism = parallelism;

        Assert.Throws<ArgumentException>(() =>
            Argon2idKeyDerivation.DeriveKek(TestMasterPassword, p));
    }

    [Fact]
    public void DeriveKek_RejectsBadSaltWithoutKdfWork()
    {
        VaultKdfParameters p = TestParameters();
        p.Salt = "not base64***";
        Assert.Throws<ArgumentException>(() =>
            Argon2idKeyDerivation.DeriveKek(TestMasterPassword, p));
    }

    [Theory]
    [InlineData("short")]
    [InlineData("")]
    public void DeriveKek_RejectsInvalidMasterPassword(string candidate)
    {
        Assert.Throws<ArgumentException>(() =>
            Argon2idKeyDerivation.DeriveKek(candidate, TestParameters()));
    }

    internal static VaultKdfParameters TestParameters() => new()
    {
        Salt = Convert.ToBase64String(Enumerable.Range(1, 16).Select(i => (byte)i).ToArray()),
        MemoryKiB = ValidationLimits.ArgonMemoryMinKiB, // Fastest policy-approved test settings
        Iterations = ValidationLimits.ArgonIterationsMin,
        Parallelism = 1
    };
}
