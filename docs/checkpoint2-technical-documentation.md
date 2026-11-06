# Secure Password Manager
## Checkpoint 2: technical documentation

**Project:** Offline Windows password manager  
**Implementation:** C# / .NET 10 / WPF  

## 1. Scope and implemented functions

Secure Password Manager is a single-user Windows desktop application. It stores credentials in a local encrypted vault and requires a master password before the entries can be accessed. The application does not provide accounts on a remote server, synchronization, browser integration, or network services.

At the current checkpoint, a user can create a vault, unlock an existing vault, add or modify credentials, delete entries, search the saved list, copy an entry password, and lock the vault manually. The interface has two layouts: full-width list rows and a card view. Each entry can contain a service title, username, password, website, and notes. Stored passwords are not rendered as ordinary text in either layout.

The project has a working WPF interface, Core library, and xUnit test project. Security-sensitive operations are handled by Core; the WPF application is responsible for input collection, presentation, and user interaction.

## 2. Solution organization

| Component | Location | Responsibility |
| --- | --- | --- |
| Desktop application | `src/PasswordManager.App/` | WPF screens, masked credential editor, list/card presentation, clipboard handling, shortcut restrictions |
| Core models | `src/PasswordManager.Core/Models/` | Credential input, encrypted vault document, encrypted index, display summaries |
| Input validation | `src/PasswordManager.Core/Validation/` | Input limits, vault structural validation, validation results |
| Cryptography | `src/PasswordManager.Core/Security/` | Argon2id derivation, random key creation, AES-GCM encryption and key wrapping |
| Vault persistence | `src/PasswordManager.Core/Storage/` | Encrypted record operations, index verification, strict JSON parsing, local file access |
| Session control | `src/PasswordManager.Core/UserManagement/` | Unlocking, authorization checks, manual and automatic locking, retry delays |
| Automated tests | `tests/PasswordManager.Core.Tests/` | Unit and security regression tests |

The application references `PasswordManager.Core`. Tests reference the same Core library and use temporary directories for storage scenarios. There is no separate service or database process.

## 3. Data models and validation

`CredentialInput` contains `Title`, `Username`, `Password`, `Url`, and `Notes`. This model carries a plaintext password while an operation is in progress; it is not a storage-file representation. Its `ToString()` method deliberately avoids printing the fields. `VaultEntrySummary` provides password-free data for the credential list, including a title, username, website, and notes. The website and notes are obtained from authenticated encrypted records when summaries are generated.

`CredentialValidator` checks required fields, length limits, UTF-16 validity, and disallowed control characters. Notes permit normal multiline characters. Passwords are not trimmed, case-folded, or normalized, since doing so would change their values. Validation results contain field names and error codes rather than rejected input.

The current limits are:

| Input or resource | Limit |
| --- | --- |
| Master password | 12–1,024 characters |
| Credential password | 1–4,096 characters |
| Service title | 1–128 characters |
| Username | Up to 256 characters |
| Website | Up to 2,048 characters |
| Notes | Up to 16,384 characters |
| Encrypted vault file | 8 MiB |
| Credential records per vault | 1,024 |
| Individual encrypted record | 128 KiB maximum ciphertext |
| Encrypted index | 256 KiB maximum ciphertext |

The vault loader checks the file size before allocating a buffer. `VaultDocumentValidator` rejects unsupported versions, invalid identifiers, duplicate record IDs, invalid Base64, wrong nonce or tag lengths, unreasonable key-derivation settings, and excessive record counts. `StrictVaultJson` disallows duplicate properties, unknown JSON properties, and overly deep structures. These checks are applied to vault data as untrusted input, even though it was previously written by the application.

## 4. Cryptographic design

A new vault receives an independently generated 256-bit random vault key. The master password is processed by Argon2id to derive a 256-bit Key Encryption Key (KEK), which is used to encrypt the vault key. This separates the master password from the key used to protect credential records.

`Argon2idKeyDerivation` uses the `Konscious.Security.Cryptography.Argon2` package (version 1.3.1). The creation defaults are a random 16-byte salt, 64 MiB memory, three iterations, and parallelism one. The application validates KDF settings loaded from disk before running Argon2id. Accepted memory settings are 32–256 MiB, with bounded iterations and parallelism.

The vault key, encrypted index, and credential records are protected with AES-256-GCM using .NET's `AesGcm` implementation. Each encryption uses a fresh random 12-byte nonce and a 16-byte authentication tag. Additional authenticated data (AAD) distinguishes the different operations:

- Key wrapping: `SPM/v1/key-wrap`
- Encrypted index: `SPM/v1/index`
- Individual record: `SPM/v1/record/<record-id>`

The record identifier in the AAD prevents encrypted record content from being reassigned to a different identifier without causing authentication failure. A decryption operation must authenticate successfully before plaintext is accepted. The cryptographic code clears temporary mutable keys, byte buffers, nonces, and tags where possible. Plaintext stored in managed C# strings cannot be reliably erased immediately and remains a known limitation.

The master password is not saved as plaintext or as a separate password hash. Correct authentication is established by successfully deriving the KEK, decrypting the wrapped vault key, and validating the encrypted index.

## 5. Vault format and local persistence

The vault is stored as versioned JSON containing cryptographic metadata and Base64-encoded encrypted data. The top-level `VaultFileDocument` contains `magic`, `formatVersion`, `kdf`, `wrappedVaultKey`, `index`, and `records`. The current magic value is `SPM1`, and the format version is `1`. Each encrypted blob has a `nonce`, `ciphertext`, and `tag`. A record also contains its UUID.

The index is encrypted and authenticated. It lists expected record identifiers, titles, usernames, and a SHA-256 fingerprint for each encrypted record. The fingerprint covers the record identifier, nonce, ciphertext, and tag. On opening a vault, Core verifies that every index entry matches a record and that no record is missing, extra, duplicated, or altered. The fingerprints are useful because they are stored *inside* an authenticated encrypted index; a standalone unkeyed hash would not authenticate the vault.

By default, the vault file is written to:

`%LOCALAPPDATA%\SecurePasswordManager\vault.spm`

The application also uses a `vault.lock` file to prevent simultaneous access by cooperating instances. Encrypted save files are staged with unpredictable `.vault-*.tmp` names in the same directory, created with `FileMode.CreateNew`. A new vault is committed with `File.Move`; subsequent saves use `File.Replace`. The complete encrypted document is flushed before replacement. If writing or replacing the file fails, the previous vault is intended to remain intact; the session layer locks after a failed save.

The loader rejects a vault directory or target path identified as a reparse point. These checks reduce exposure to link-based attacks but do not fully remove race conditions or prevent a process running with the same Windows user's permissions from interfering with files. Explicit Windows ACL hardening beyond the usual per-user LocalAppData directory is not implemented in this checkpoint.

## 6. Application operations

### Creating a vault

The user enters a master password and confirmation in masked WPF fields. Validation must succeed before Core creates a random vault key, derives the KEK, wraps the key, constructs an encrypted empty index, and writes the first vault file. `VaultRepository.CreateNew` uses create-only file semantics so an existing vault is not overwritten. The new vault opens in an authenticated session after creation.

### Unlocking

`VaultSessionManager.Unlock` calls `VaultRepository.Open`. The repository obtains an exclusive vault lock, loads and validates the encrypted file, derives the KEK, authenticates the wrapped key, decrypts the index, and checks record consistency. A wrong password or altered protected data leaves the vault locked. The interface presents a generic message instead of disclosing cryptographic internals.

### Working with entries

All credential operations go through `VaultSessionManager`, which holds the unlocked vault privately. The UI cannot directly obtain the encryption key. `ListEntries` returns summaries without passwords. Opening the editor for an existing entry or copying a stored password requires a separate authenticated credential lookup. Add, edit, and delete operations validate input, update the encrypted record and authenticated index, and save the modified vault before returning success.

### Locking

The session starts locked. Manual locking, expiry after inactivity, disposal, and certain integrity or storage failures revoke access and dispose the unlocked vault. Disposing the vault clears its mutable key buffer and releases the cooperating-process file lock. The UI removes its displayed entries and clears sensitive input controls when it detects the lock.

## 7. Session and interface behavior

`VaultSessionManager` uses a monotonic clock to measure user inactivity. The default timeout is five minutes, and the interface has selectable timeout settings. The main window shows a live countdown based on the Core session's actual remaining time. Periodic display updates do not count as user activity. Credential operations and input events register activity, while an independent Core timer checks expiry.

Repeated unsuccessful unlocks trigger short, increasing retry delays, reaching a maximum of eight seconds. This only limits attempts through the running application. It is not a substitute for Argon2id against offline password guessing.

The WPF interface uses a light-green and white color palette. The credential list supports full-width rows or wrapping cards, search by title, username, or website, and displays the website and notes when provided. Password fields use `PasswordBox`; stored passwords are not printed in the credential views. Selecting an entry enables the edit, copy-password, and delete actions.

The **Copy password** action deliberately transfers the selected password to the Windows clipboard. `PasswordClipboardGuard` attempts to clear it after **10 seconds**, or when the vault locks, but only if the current clipboard content still matches the password placed there by the application. The matching check uses an ephemeral HMAC. Clipboard history, synchronization, and third-party clipboard tools remain outside the application's control.

WPF text-box undo history is disabled globally, and `UndoSuppression` blocks Undo/Redo commands and Ctrl+Z/Ctrl+Y keyboard shortcuts in the main and editor windows. This prevents UI undo from restoring cleared fields or interfering with the forms. Persistence safety is handled separately by the encrypted storage layer; suppressing Ctrl+Z is not a replacement for valid save logic.

## 8. Error handling and test evidence

Authentication, integrity, parsing, and storage failures stop the affected operation. The interface reports generic messages, and a failed save revokes the unlocked session. The encrypted index and individual AES-GCM tags are checked before protected data is returned. The storage code avoids truncating the existing file as a fallback when replacement fails.

The automated test project covers validation limits, Argon2id parameters, AES-GCM round trips, wrong keys, modified nonces or authentication tags, vault creation and reopening, add/edit/delete persistence, malformed JSON, missing or replaced encrypted records, session authorization, retry delays, expiry, and failed-save behavior. The test source files include:

- `CredentialValidatorTests.cs` and `VaultDocumentValidatorTests.cs`
- `Argon2idKeyDerivationTests.cs`, `VaultAesGcmTests.cs`, and `VaultKeyManagerTests.cs`
- `EncryptedVaultStorageTests.cs` and `VaultTamperingTests.cs`
- `VaultSessionManagerTests.cs`

The reported Windows verification used .NET SDK **10.0.401**. The Release solution build completed with **zero warnings and zero errors**, and the current xUnit run passed **86 tests, with zero failures**. The interface was also checked manually for creating and unlocking a vault, managing credentials, persistence, auto-lock, list/card display, and disabled undo shortcuts. These are reported development results; a separate independent security assessment has not been performed.

## 9. Build and run on Windows

Requirements: Windows 10/11, .NET 10 SDK, and access to configured NuGet package sources for the initial package restore. Run the commands from the directory containing `SecurePasswordManager.sln`:

```powershell
dotnet restore SecurePasswordManager.sln
dotnet build SecurePasswordManager.sln -c Release
dotnet test SecurePasswordManager.sln -c Release
dotnet run --project src/PasswordManager.App/PasswordManager.App.csproj
```

The default `dotnet run` output is under `src/PasswordManager.App/bin/Debug/net10.0-windows/`. A Release build is under `bin/Release/net10.0-windows/`. These directories contain application build outputs; the encrypted vault is stored separately under LocalAppData. Deleting a build-output directory does not delete the existing vault.

Git history contains distinct commits for the design, input models, cryptography, vault storage, session management, and graphical application. No actual vault file or secret is required in the repository to build or test the project.

## 10. Security boundaries and outstanding work

Checkpoint 2 demonstrates a locally functioning, encrypted password manager. It does not establish protection against an attacker controlling the Windows account or the operating system. In particular:

- Plaintext in managed objects, process memory, or the Windows clipboard can remain accessible to software with sufficient local privileges.
- The application cannot detect a complete replacement of the vault with an older, otherwise valid encrypted version without an independent trusted state.
- Explicit Windows ACL enforcement and stronger protection against same-user path/reparse-point races require further work.
- Structured security-event logging, log rotation, and a local audit view are not implemented.
- Master-password change and recovery are not implemented. Losing the master password can make the stored vault inaccessible.

These limitations do not change the observed Checkpoint 2 results, but they remain relevant to the final project's security goals.
