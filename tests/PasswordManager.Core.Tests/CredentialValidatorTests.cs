using PasswordManager.Core.Models;
using PasswordManager.Core.Validation;

namespace PasswordManager.Core.Tests;

public sealed class CredentialValidatorTests
{
    [Fact]
    public void AcceptsAValidCredential()
    {
        var input = new CredentialInput
        {
            Title = "Example",
            Username = "account@example.test",
            Password = "not-a-real-secret!",
            Url = "https://example.test",
            Notes = "First line\nSecond line"
        };

        Assert.True(CredentialValidator.Validate(input).IsValid);
    }

    [Fact]
    public void RejectsMissingTitleAndPassword()
    {
        var result = CredentialValidator.Validate(new CredentialInput());

        Assert.False(result.IsValid);
        Assert.Contains(result.Issues, e => e.Field == "title");
        Assert.Contains(result.Issues, e => e.Field == "password");
    }

    [Fact]
    public void RejectsOversizedCredentialFields()
    {
        var result = CredentialValidator.Validate(new CredentialInput
        {
            Title = new string('a', ValidationLimits.TitleMaxChars + 1),
            Password = new string('p', ValidationLimits.CredentialPasswordMaxChars + 1)
        });

        Assert.Contains(result.Issues, e => e.Field == "title" && e.Code == "too_long");
        Assert.Contains(result.Issues, e => e.Field == "password" && e.Code == "too_long");
    }

    [Fact]
    public void RejectsControlCharactersAndInvalidUtf16()
    {
        var result = CredentialValidator.Validate(new CredentialInput
        {
            Title = "a\nnew line",
            Password = "abc\uD800"
        });

        Assert.Contains(result.Issues, e => e.Field == "title" && e.Code == "invalid_characters");
        Assert.Contains(result.Issues, e => e.Field == "password" && e.Code == "invalid_characters");
    }

    [Fact]
    public void PermitsWhitespaceWithinPasswordsWithoutTrimming()
    {
        var input = new CredentialInput { Title = "Example", Password = "  spaced secret  " };
        Assert.True(CredentialValidator.Validate(input).IsValid);
        Assert.Equal("  spaced secret  ", input.Password);
    }

    [Theory]
    [InlineData("short")]
    [InlineData("")]
    public void RejectsShortMasterPasswords(string password)
    {
        Assert.False(CredentialValidator.ValidateMasterPassword(password).IsValid);
    }

    [Fact]
    public void AcceptsMasterPasswordWithoutNormalizingIt()
    {
        Assert.True(CredentialValidator.ValidateMasterPassword("  master passphrase  ").IsValid);
    }

    [Fact]
    public void DoesNotPrintCredentialsThroughToString()
    {
        var input = new CredentialInput { Title = "Example", Password = "DO-NOT-PRINT-THIS" };
        Assert.DoesNotContain("DO-NOT-PRINT-THIS", input.ToString());
    }
}
