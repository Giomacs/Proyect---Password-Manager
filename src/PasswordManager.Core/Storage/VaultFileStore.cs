using System.Security.Cryptography;
using PasswordManager.Core.Models;
using PasswordManager.Core.Validation;

namespace PasswordManager.Core.Storage;

/// <summary>
/// Binary-safe persistence for the version-1 ENCRYPTED JSON vault.
/// Never writes decrypted indexes or credentials. Locking serializes
/// cooperating application processes, not malicious same-user processes.
/// </summary>
internal sealed class VaultFileStore
{
    internal const string FileName = "vault.spm";
    private readonly string _folder;
    private readonly string _path;
    private readonly string _lockPath;

    public VaultFileStore()
        : this(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SecurePasswordManager")) { }

    // For isolated automated tests only (friend assembly).
    internal VaultFileStore(string directory)
    {
        if (string.IsNullOrWhiteSpace(directory))
            throw new ArgumentException("Invalid storage directory.", nameof(directory));

        _folder = Path.GetFullPath(directory);
        _path = Path.Combine(_folder, FileName);
        _lockPath = Path.Combine(_folder, "vault.lock");
    }

    internal string VaultPath => _path;
    public bool Exists => File.Exists(_path);

    internal FileStream AcquireLock()
    {
        EnsurePrivateFolder();
        RejectLinkIfPresent(_lockPath);
        try
        {
            // The OS owns the exclusivity; the lock file itself may persist.
            return new FileStream(_lockPath, FileMode.OpenOrCreate,
                FileAccess.ReadWrite, FileShare.None);
        }
        catch (IOException)
        {
            throw new IOException("The vault is currently in use or inaccessible.");
        }
    }

    internal VaultFileDocument Read()
    {
        EnsurePrivateFolder();
        RejectLinkIfPresent(_path);

        using var stream = new FileStream(_path, FileMode.Open,
            FileAccess.Read, FileShare.Read);

        long size = stream.Length;
        if (!VaultDocumentValidator.ValidateFileSize(size).IsValid)
            throw new InvalidDataException("Invalid vault data.");

        byte[] data = new byte[checked((int)size)];
        try
        {
            stream.ReadExactly(data);
            // Detect an appended file during the read rather than quietly ignoring it.
            if (stream.ReadByte() != -1)
                throw new InvalidDataException("Invalid vault data.");

            VaultFileDocument document = StrictVaultJson.Deserialize<VaultFileDocument>(data);
            if (!VaultDocumentValidator.Validate(document).IsValid)
                throw new InvalidDataException("Invalid vault data.");
            return document;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(data);
        }
    }

    internal void Write(VaultFileDocument document, bool createOnly)
    {
        EnsurePrivateFolder();
        if (!VaultDocumentValidator.Validate(document).IsValid)
            throw new InvalidDataException("Invalid vault data.");

        byte[] data = StrictVaultJson.Serialize(document);
        string? temporary = null;
        try
        {
            if (!VaultDocumentValidator.ValidateFileSize(data.Length).IsValid)
                throw new InvalidDataException("Vault exceeds its maximum size.");

            // Both files are in the same per-user directory. Avoid check-then-create
            // for temporary files: FileMode.CreateNew fails if the name exists.
            temporary = Path.Combine(_folder,
                ".vault-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16)) + ".tmp");

            using (var stream = new FileStream(temporary, FileMode.CreateNew,
                FileAccess.Write, FileShare.None))
            {
                stream.Write(data);
                stream.Flush(flushToDisk: true);
            }

            if (createOnly)
            {
                // Fails rather than overwriting an existing vault.
                File.Move(temporary, _path);
            }
            else
            {
                RejectLinkIfPresent(_path);
                // No destructive truncate/fallback: if replace fails, old vault remains.
                File.Replace(temporary, _path, destinationBackupFileName: null);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(data);
            if (temporary is not null)
            {
                try { File.Delete(temporary); }
                catch (IOException) { /* Best-effort removal of encrypted temp bytes. */ }
                catch (UnauthorizedAccessException) { /* Same as above. */ }
            }
        }
    }

    private void EnsurePrivateFolder()
    {
        Directory.CreateDirectory(_folder);
        // Defense in depth. This is NOT a complete solution to races by a
        // process already running as the same OS user.
        if ((File.GetAttributes(_folder) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Vault location is not a regular directory.");
    }

    private static void RejectLinkIfPresent(string path)
    {
        try
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Vault path is not a regular file.");
        }
        catch (FileNotFoundException) { }
        catch (DirectoryNotFoundException) { }
    }
}
