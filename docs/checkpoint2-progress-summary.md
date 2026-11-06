# Secure Password Manager
## Checkpoint 2: progress summary

**Github Link:** https://github.com/Giomacs/Proyect---Password-Manager
**Project:** Offline Windows password manager  
**Technology:** C# / .NET 10 / WPF  

The application now provides a working local vault for a single Windows user. A new vault can be created using a master password, and an existing vault must be successfully unlocked before any stored credentials can be accessed. Each entry supports a service title, username, password, website, and optional notes. Users can add, edit, delete, search, and copy stored passwords through the desktop interface.

### Implemented requirements

**Vault storage and persistence.** Encrypted credentials are saved in `%LOCALAPPDATA%\SecurePasswordManager\vault.spm`. Entries remain available after closing and reopening the application. Saves use a temporary encrypted file followed by replacement of the previous vault. An exclusive lock prevents simultaneous use by cooperating application instances.

**Encryption at rest.** A random 256-bit vault key encrypts the credential records and index with AES-256-GCM. Argon2id derives a key from the master password to protect the vault key. The implementation uses random salts and nonces, authenticated tags, and an encrypted index that checks for missing, replaced, or modified records.

**Master-password authentication.** The vault starts locked. Unlocking requires successful decryption of the wrapped vault key and verification of the encrypted index. Incorrect passwords and integrity failures do not grant access. The session supports manual locking, an inactivity timeout (five minutes by default), a remaining-time display, and short retry delays after repeated failed unlock attempts.

**Usable desktop interface.** The WPF application has vault-creation and unlock screens, a masked credential editor, search, and selectable full-width List and Cards layouts. Usernames, websites, and notes can be displayed, but stored passwords are never printed directly in the entry list. Password copying is an explicit action; the application attempts to clear the clipboard after 10 seconds. Text undo/redo is disabled in the interface.

**Reproducible build and development history.** The solution contains separate WPF, Core, and xUnit test projects. Git history records incremental implementation commits. A reviewer can restore, build, test, and run the application from the repository root:

```powershell
dotnet restore SecurePasswordManager.sln
dotnet build SecurePasswordManager.sln -c Release
dotnet test SecurePasswordManager.sln -c Release
dotnet run --project src/PasswordManager.App/PasswordManager.App.csproj
```

### Verification

On Windows with **.NET SDK 10.0.401**, the Release build completed with **0 warnings and 0 errors**. The current automated test run passed **86 of 86 tests**. Tests cover validation, encryption and decryption, incorrect keys, tampered encrypted data, vault persistence, session control, and error conditions. The application was also exercised manually for credential operations, locking, and interface behavior.

### Remaining limitations

The vault is designed for local, offline use and does not protect against a compromised operating system. Clipboard history and managed-memory copies cannot be completely controlled. Full rollback of an otherwise valid vault is not detected. Security-event logging, explicit Windows file-permission hardening, and master-password change remain outside the implemented checkpoint functionality.
