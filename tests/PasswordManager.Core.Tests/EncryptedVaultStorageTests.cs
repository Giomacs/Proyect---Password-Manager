using System.Security.Cryptography;
using System.Text.Json;
using PasswordManager.Core.Models;
using PasswordManager.Core.Storage;
using Xunit;

namespace PasswordManager.Core.Tests;

public sealed class EncryptedVaultStorageTests
{
    private const string Master = "A-Valid-Master-Password-for-Tests";
    private const string WrongMaster = "This-Is-Not-The-Correct-Password";
    private const string Secret = "S3cret-For-Test-Only-92817!";

    private static CredentialInput Example(string title = "Example Website") => new()
    {
        Title = title,
        Username = "demo-user",
        Password = Secret,
        Url = "https://example.invalid/login",
        Notes = "Synthetic test note"
    };

    private static VaultRepository Repository(TemporaryVaultDirectory directory)
        => new(directory.Path);

    private static UnlockedVault NewVault(VaultRepository repository)
        => repository.CreateNewWithParameters(Master, Argon2idKeyDerivationTests.TestParameters());

    [Fact]
    public void CreateEmptyVault_IsEncryptedAndCanBeReopened()
    {
        using var directory = new TemporaryVaultDirectory();
        var repo = Repository(directory);
        Assert.False(repo.VaultExists);

        using (UnlockedVault opened = NewVault(repo))
            Assert.Empty(opened.ListEntries());

        Assert.True(repo.VaultExists);
        string json = File.ReadAllText(directory.VaultFile);
        Assert.Contains("\"wrappedVaultKey\"", json);
        Assert.Contains("\"index\"", json);
        Assert.DoesNotContain(Master, json);

        using var again = repo.Open(Master);
        Assert.Empty(again.ListEntries());
    }

    [Fact]
    public void CredentialRoundTrip_PersistsOnlyEncryptedRecords()
    {
        using var directory = new TemporaryVaultDirectory();
        var repo = Repository(directory);
        Guid id;
        using (UnlockedVault opened = NewVault(repo))
        {
            id = opened.AddCredential(Example());
            Assert.True(opened.HasUnsavedChanges);
            opened.Save();
            Assert.False(opened.HasUnsavedChanges);
        }

        string stored = File.ReadAllText(directory.VaultFile);
        Assert.DoesNotContain(Secret, stored);
        Assert.DoesNotContain("demo-user", stored);
        Assert.DoesNotContain("Example Website", stored);
        Assert.DoesNotContain("Synthetic test note", stored);

        using var restored = repo.Open(Master);
        VaultEntrySummary summary = Assert.Single(restored.ListEntries());
        Assert.Equal(id, summary.Id);
        Assert.Equal("Example Website", summary.Title);
        Assert.Equal("demo-user", summary.Username);
        Assert.Equal("https://example.invalid/login", summary.Url);
        Assert.Equal("Synthetic test note", summary.Notes);
        Assert.True(summary.HasWebsite);
        Assert.True(summary.HasNotes);
        Assert.DoesNotContain(Secret, summary.ToString());
        Assert.DoesNotContain("Synthetic test note", summary.ToString());
        CredentialInput actual = restored.GetCredential(id);
        Assert.Equal(Secret, actual.Password);
        Assert.Equal("https://example.invalid/login", actual.Url);
    }

    [Fact]
    public void DisplaySummary_OmitsOptionalWebsiteAndNotes()
    {
        using var directory = new TemporaryVaultDirectory();
        var repo = Repository(directory);
        using var opened = NewVault(repo);
        opened.AddCredential(new CredentialInput
        {
            Title = "Local-only entry",
            Username = "demo-user",
            Password = Secret
        });
        opened.Save();

        VaultEntrySummary summary = Assert.Single(opened.ListEntries());
        Assert.False(summary.HasWebsite);
        Assert.False(summary.HasNotes);
        Assert.Null(summary.Url);
        Assert.Null(summary.Notes);
    }

    [Fact]
    public void IncorrectMasterPassword_DoesNotOpenVault()
    {
        using var directory = new TemporaryVaultDirectory();
        var repo = Repository(directory);
        using (NewVault(repo)) { }

        Assert.Throws<CryptographicException>(() => repo.Open(WrongMaster));
        // A failed open must release the lock for a later correct attempt.
        using var valid = repo.Open(Master);
        Assert.Empty(valid.ListEntries());
    }

    [Fact]
    public void UpdateAndDelete_ArePersistedAfterSave()
    {
        using var directory = new TemporaryVaultDirectory();
        var repo = Repository(directory);
        Guid id;
        using (UnlockedVault vault = NewVault(repo))
        {
            id = vault.AddCredential(Example());
            vault.Save();
        }

        using (UnlockedVault vault = repo.Open(Master))
        {
            Assert.True(vault.UpdateCredential(id, Example("Updated Site")));
            Assert.Equal("Updated Site", vault.GetCredential(id).Title);
            vault.Save();
        }

        using (UnlockedVault vault = repo.Open(Master))
        {
            Assert.Equal("Updated Site", Assert.Single(vault.ListEntries()).Title);
            Assert.True(vault.DeleteCredential(id));
            Assert.False(vault.DeleteCredential(id));
            vault.Save();
        }

        using var empty = repo.Open(Master);
        Assert.Empty(empty.ListEntries());
    }

    [Fact]
    public void UncommittedEdits_AreNotWrittenToDisk()
    {
        using var directory = new TemporaryVaultDirectory();
        var repo = Repository(directory);
        using (UnlockedVault vault = NewVault(repo))
        {
            vault.AddCredential(Example());
            // Without Save(), closing discards the in-memory changes.
        }
        using var reopened = repo.Open(Master);
        Assert.Empty(reopened.ListEntries());
    }

    [Fact]
    public void TwoSimultaneousSessions_AreNotAllowed()
    {
        using var directory = new TemporaryVaultDirectory();
        var repo = Repository(directory);
        using (UnlockedVault first = NewVault(repo))
        {
            Assert.Throws<IOException>(() => repo.Open(Master));
        }
        using var second = repo.Open(Master);
        Assert.Empty(second.ListEntries());
    }

    [Fact]
    public void DisposedVault_RejectsOperations()
    {
        using var directory = new TemporaryVaultDirectory();
        var repo = Repository(directory);
        UnlockedVault vault = NewVault(repo);
        vault.Dispose();
        Assert.Throws<ObjectDisposedException>(() => vault.AddCredential(Example()));
        Assert.Throws<ObjectDisposedException>(() => vault.GetCredential(Guid.NewGuid()));
        Assert.Throws<ObjectDisposedException>(() => vault.Save());
    }

    [Fact]
    public void SecondCreate_DoesNotOverwriteExistingVault()
    {
        using var directory = new TemporaryVaultDirectory();
        var repo = Repository(directory);
        using (NewVault(repo)) { }
        byte[] before = File.ReadAllBytes(directory.VaultFile);
        Assert.Throws<IOException>(() => NewVault(repo));
        Assert.Equal(before, File.ReadAllBytes(directory.VaultFile));
    }

    [Fact]
    public void RejectsInvalidCredentialWithoutSavingAnything()
    {
        using var directory = new TemporaryVaultDirectory();
        var repo = Repository(directory);
        using (UnlockedVault opened = NewVault(repo))
        {
            Assert.Throws<ArgumentException>(() => opened.AddCredential(new CredentialInput
            {
                Title = "", Password = "x"
            }));
            Assert.Empty(opened.ListEntries());
            Assert.False(opened.HasUnsavedChanges);
        }
        using var again = repo.Open(Master);
        Assert.Empty(again.ListEntries());
    }

    [Fact]
    public void OversizedSave_DoesNotDamagePreviousVaultFile()
    {
        using var directory = new TemporaryVaultDirectory();
        var repo = Repository(directory);
        using (UnlockedVault vault = NewVault(repo))
        {
            vault.AddCredential(Example("Existing"));
            vault.Save();
            byte[] before = File.ReadAllBytes(directory.VaultFile);

            // Stay under the per-record limit, but exceed the 8 MiB whole-vault limit.
            string largeNote = new('N', 15_000);
            for (int i = 0; i < 440; i++)
            {
                vault.AddCredential(new CredentialInput
                {
                    Title = "Oversize " + i.ToString(),
                    Password = "test-only-secret",
                    Notes = largeNote
                });
            }

            Assert.Throws<InvalidDataException>(() => vault.Save());
            Assert.True(vault.HasUnsavedChanges);
            Assert.True(before.SequenceEqual(File.ReadAllBytes(directory.VaultFile)));
        }

        using var reopened = repo.Open(Master);
        Assert.Equal("Existing", Assert.Single(reopened.ListEntries()).Title);
    }

    [Fact]
    public void OptionalNullUsername_RoundTripsCorrectly()
    {
        using var directory = new TemporaryVaultDirectory();
        var repo = Repository(directory);
        Guid id;
        using (UnlockedVault vault = NewVault(repo))
        {
            id = vault.AddCredential(new CredentialInput
            {
                Title = "No username", Password = Secret
            });
            vault.Save();
        }
        using var reopened = repo.Open(Master);
        Assert.Null(reopened.GetCredential(id).Username);
    }

    private sealed class TemporaryVaultDirectory : IDisposable
    {
        public string Path { get; } = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(), "SPM-Stage3-" + Guid.NewGuid().ToString("N"));

        public string VaultFile => System.IO.Path.Combine(Path, "vault.spm");

        public void Dispose()
        {
            if (Directory.Exists(Path)) Directory.Delete(Path, recursive: true);
        }
    }
}
