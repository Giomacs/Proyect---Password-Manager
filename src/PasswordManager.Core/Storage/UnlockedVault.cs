using System.Security.Cryptography;
using PasswordManager.Core.Models;
using PasswordManager.Core.Security;
using PasswordManager.Core.Validation;

namespace PasswordManager.Core.Storage;

/// <summary>
/// Authenticated, unlocked vault. Holds a vault key only until Dispose().
/// Always dispose; Section 4 will own this object via a lockable session.
/// </summary>
public sealed class UnlockedVault : IDisposable
{
    private readonly object _gate = new();
    private readonly VaultFileStore _store;
    private readonly FileStream _heldLock;
    private readonly byte[] _vaultKey;
    private VaultFileDocument _document;
    private readonly VaultIndexDocument _index;
    private bool _disposed;
    private bool _dirty;

    internal UnlockedVault(VaultFileStore store, FileStream heldLock,
        byte[] vaultKey, VaultFileDocument document, VaultIndexDocument index)
    {
        _store = store;
        _heldLock = heldLock;
        _vaultKey = vaultKey;
        _document = document;
        _index = index;
    }

    public bool HasUnsavedChanges
    {
        get { lock (_gate) { EnsureOpen(); return _dirty; } }
    }

    /// <summary>Lists limited metadata, never credential passwords.</summary>
    public IReadOnlyList<VaultEntrySummary> ListEntries()
    {
        lock (_gate)
        {
            EnsureOpen();
            return _index.Entries!.Select(entry => new VaultEntrySummary(
                Guid.ParseExact(entry.Id!, "D"), entry.Title!, entry.Username)).ToArray();
        }
    }

    public Guid AddCredential(CredentialInput input)
    {
        lock (_gate)
        {
            EnsureOpen();
            ValidateInput(input);
            if (_document.Records!.Count >= ValidationLimits.VaultMaxRecords)
                throw new InvalidOperationException("Vault record limit reached.");

            Guid id = Guid.NewGuid();
            VaultEncryptedRecord encrypted = EncryptCredential(id, input);
            _document.Records.Add(encrypted);
            _index.Entries!.Add(ToIndexEntry(encrypted, input));
            _dirty = true;
            return id;
        }
    }

    public bool UpdateCredential(Guid id, CredentialInput input)
    {
        lock (_gate)
        {
            EnsureOpen();
            ValidateInput(input);
            int position = _document.Records!.FindIndex(record => RecordIdIs(record, id));
            if (position < 0) return false;

            VaultEncryptedRecord encrypted = EncryptCredential(id, input);
            int idx = _index.Entries!.FindIndex(entry => IndexIdIs(entry, id));
            if (idx < 0) throw new InvalidDataException("Vault index is inconsistent.");

            _document.Records[position] = encrypted;
            _index.Entries[idx] = ToIndexEntry(encrypted, input);
            _dirty = true;
            return true;
        }
    }

    public bool DeleteCredential(Guid id)
    {
        lock (_gate)
        {
            EnsureOpen();
            int recordPos = _document.Records!.FindIndex(record => RecordIdIs(record, id));
            if (recordPos < 0) return false;
            int indexPos = _index.Entries!.FindIndex(entry => IndexIdIs(entry, id));
            if (indexPos < 0) throw new InvalidDataException("Vault index is inconsistent.");

            _document.Records.RemoveAt(recordPos);
            _index.Entries.RemoveAt(indexPos);
            _dirty = true;
            return true;
        }
    }

    /// <summary>
    /// Returns a plaintext credential in a managed object. The caller must
    /// minimize its lifetime and never log or print its Password property.
    /// </summary>
    public CredentialInput GetCredential(Guid id)
    {
        lock (_gate)
        {
            EnsureOpen();
            VaultEncryptedRecord? record = _document.Records!.Find(r => RecordIdIs(r, id));
            VaultIndexEntry? expected = _index.Entries!.Find(e => IndexIdIs(e, id));
            if (record is null || expected is null)
                throw new KeyNotFoundException("Credential entry not found.");

            byte[] plaintext = VaultAesGcm.DecryptRecord(_vaultKey, record);
            try
            {
                CredentialInput input = StrictVaultJson.Deserialize<CredentialInput>(plaintext);
                if (!CredentialValidator.Validate(input).IsValid ||
                    !StringComparer.Ordinal.Equals(input.Title, expected.Title) ||
                    !StringComparer.Ordinal.Equals(input.Username ?? string.Empty, expected.Username))
                    throw new InvalidDataException("Vault record data is inconsistent.");
                return input;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
    }

    /// <summary>
    /// Commits the fully encrypted document. If replacement fails, the old
    /// complete vault remains on disk and _dirty stays true for retry.
    /// </summary>
    public void Save()
    {
        lock (_gate)
        {
            EnsureOpen();
            if (!_dirty) return;

            VerifyIndex(_index, _document.Records!);
            VaultEncryptedBlob encryptedIndex = EncryptIndex(_vaultKey, _index);
            var replacement = new VaultFileDocument
            {
                Magic = "SPM1",
                FormatVersion = 1,
                Kdf = _document.Kdf,
                WrappedVaultKey = _document.WrappedVaultKey,
                Index = encryptedIndex,
                Records = new List<VaultEncryptedRecord>(_document.Records!)
            };

            _store.Write(replacement, createOnly: false);
            _document = replacement;
            _dirty = false;
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            CryptographicOperations.ZeroMemory(_vaultKey);
            _index.Entries?.Clear();
            _document.Records?.Clear();
            _heldLock.Dispose();
        }
        GC.SuppressFinalize(this);
    }

    internal static VaultEncryptedBlob EncryptIndex(byte[] key, VaultIndexDocument index)
    {
        byte[] plaintext = StrictVaultJson.Serialize(index);
        try { return VaultAesGcm.EncryptIndex(key, plaintext); }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    internal static VaultIndexDocument DecryptIndex(byte[] key, VaultEncryptedBlob? encrypted)
    {
        byte[] plaintext = VaultAesGcm.DecryptIndex(key, encrypted);
        try { return StrictVaultJson.Deserialize<VaultIndexDocument>(plaintext); }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    /// <summary>
    /// Requires exact agreement between the authenticated index and ALL stored
    /// records, including their encrypted bytes. Prevents undetected deletion,
    /// insertion and replacement of records in an otherwise valid vault.
    /// </summary>
    internal static void VerifyIndex(VaultIndexDocument index, List<VaultEncryptedRecord> records)
    {
        if (index.FormatVersion != 1 || index.Entries is null ||
            index.Entries.Count > ValidationLimits.VaultMaxRecords ||
            index.Entries.Count != records.Count)
            throw new InvalidDataException("Vault index is inconsistent.");

        var map = new Dictionary<Guid, VaultEncryptedRecord>();
        foreach (VaultEncryptedRecord record in records)
        {
            if (!Guid.TryParseExact(record.Id, "D", out Guid id) || id == Guid.Empty ||
                !map.TryAdd(id, record))
                throw new InvalidDataException("Vault records are inconsistent.");
        }

        var seen = new HashSet<Guid>();
        foreach (VaultIndexEntry entry in index.Entries)
        {
            if (entry is null ||
                !Guid.TryParseExact(entry.Id, "D", out Guid id) || id == Guid.Empty ||
                !StringComparer.Ordinal.Equals(entry.Id, id.ToString("D")) ||
                !seen.Add(id) || !map.TryGetValue(id, out VaultEncryptedRecord? record))
                throw new InvalidDataException("Vault index is inconsistent.");

            if (entry.Title is null || entry.Username is null ||
                !CredentialValidator.Validate(new CredentialInput
                {
                    Title = entry.Title,
                    Username = entry.Username,
                    Password = "x"
                }).IsValid)
                throw new InvalidDataException("Invalid vault index entry.");

            string expected = RecordIntegrity.Fingerprint(record);
            if (entry.CiphertextSha256 is null ||
                !StringComparer.Ordinal.Equals(entry.CiphertextSha256, expected))
                throw new InvalidDataException("Vault record integrity verification failed.");
        }
    }

    private VaultEncryptedRecord EncryptCredential(Guid id, CredentialInput input)
    {
        byte[] serialized = StrictVaultJson.Serialize(input);
        try { return VaultAesGcm.EncryptRecord(_vaultKey, id, serialized); }
        finally { CryptographicOperations.ZeroMemory(serialized); }
    }

    private static VaultIndexEntry ToIndexEntry(VaultEncryptedRecord record, CredentialInput input)
        => new()
        {
            Id = record.Id,
            Title = input.Title,
            Username = input.Username ?? string.Empty,
            CiphertextSha256 = RecordIntegrity.Fingerprint(record)
        };

    private static void ValidateInput(CredentialInput? input)
    {
        if (!CredentialValidator.Validate(input).IsValid)
            throw new ArgumentException("Invalid credential fields.", nameof(input));
    }

    private static bool RecordIdIs(VaultEncryptedRecord record, Guid id)
        => Guid.TryParseExact(record.Id, "D", out Guid found) && found == id;

    private static bool IndexIdIs(VaultIndexEntry entry, Guid id)
        => Guid.TryParseExact(entry.Id, "D", out Guid found) && found == id;

    private void EnsureOpen()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(UnlockedVault));
    }
}
