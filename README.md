# Secure Password Manager
Secure Password Manager is a single-user, offline Windows desktop application designed to protect locally stored credentials and detect unauthorized modification of the encrypted vault.

Version 1 has no server or network functionality. It does not use cloud accounts, synchronization, telemetry, analytics, browser extensions, or remote services.

## Scope
The application is designed to:
- run as a Windows desktop application and be publishable as an `.exe`;
- create one local encrypted vault for the current Windows user;
- authenticate access with a master password;
- store a service or title, username, password, URL, and optional notes;
- add, edit, delete, search, reveal, and copy credential entries;
- automatically lock after inactivity and support manual locking;
- detect unauthorized modification of authenticated encrypted vault data;
- minimize the amount of time decrypted passwords and cryptographic keys remain in memory;
- validate user input and vault-file data before processing it;
- save the vault using safe file-I/O operations;
- record security events without storing credentials, keys, or decrypted vault contents in logs;
- fail closed when authentication, integrity, parsing, or cryptographic operations fail;
- include automated tests, static analysis, and dependency auditing.

The following are outside the scope of version 1:
- cloud synchronization;
- remote access;
- browser autofill;
- credential sharing;
- remote password recovery;
- multi-user server accounts;
- protection against a fully compromised operating system, administrator-level malware, or a keylogger active while the vault is unlocked.

## Technology
- Language: C#
- Runtime: .NET 10
- Desktop interface: WPF
- Password-based key derivation: Argon2id through a maintained cryptographic library
- Authenticated encryption: AES-256-GCM using established .NET cryptographic APIs
- Randomness: operating-system cryptographically secure random-number generator (`RandomNumberGenerator`)
- Testing: xUnit

The project does not implement custom encryption algorithms, custom random-number generators, or custom password-hashing algorithms.

The detailed architecture, threat model, vault format, and cryptographic design are documented in [`docs/checkpoint1-design.md`](docs/checkpoint1-design.md).

## Planned screens

### Create Vault
Used when no vault exists.
- master password;
- master-password confirmation;
- password-strength and length guidance;
- Create Vault action.

### Unlock Vault
Used when an encrypted vault already exists.
- masked master-password field;
- Unlock action;
- generic authentication failure message;
- increasing delay after repeated failed attempts;
- no permanent local lockout.

### Vault
Main credential list.
- search entries;
- add entry;
- edit entry;
- delete entry;
- open entry details;
- lock vault.

Passwords remain masked in the list view.

### Entry Details
Displays one credential entry.
- title or service;
- URL;
- username;
- password;
- notes;
- reveal password;
- copy username;
- copy password;
- save and cancel actions.

### Security Settings
Contains local security options.
- change master password;
- configure automatic-lock timeout;
- lock immediately;
- view local security-event information.

## Architecture
The application is separated into a desktop interface and a security-sensitive core library.

```text
User
  |
  v
PasswordManager.App
(WPF desktop interface)
  |
  v
PasswordManager.Core
  |
  +-- UserManagement
  +-- Security
  +-- Validation
  +-- Vault
  +-- Storage
  +-- Logging
  |
  v
Local encrypted vault file
```

`PasswordManager.App` contains presentation and interaction logic.

`PasswordManager.Core` contains vault handling, cryptography, validation, session management, secure storage operations, and security logging. The interface does not access the vault file or implement cryptographic operations directly.

## Security design

### Confidentiality
Vault contents are encrypted before being written to disk. Local file permissions are also restricted to the current user where supported.

### Authentication
The vault starts in a locked state. Access requires successful authentication with the master password. Protected vault operations require an authenticated unlocked session.

### Integrity and tamper detection
Vault data is protected with authenticated encryption. Modified ciphertext or authentication data is rejected instead of being processed as valid vault content.

### Memory management
Credential records are decrypted only when needed. The application minimizes unnecessary plaintext copies and clears mutable password and key buffers where practical.

### Input validation
Both interface input and vault-file content are treated as untrusted data. File size, structure, record counts, encoded lengths, identifiers, and key-derivation parameters are checked before expensive allocation or cryptographic processing.

### Secure file I/O
The vault is stored in a private application directory. Vault saves use temporary-file and replacement operations intended to avoid unsafe check-then-use behavior and reduce the risk of partial writes.

### Logging and monitoring
Security events are recorded using fixed event types. Logs do not contain master passwords, stored passwords, usernames, URLs, notes, cryptographic keys, or decrypted vault data. Log size is bounded and rotation is planned.

### Error handling
User-facing errors do not expose cryptographic details, stack traces, file internals, or sensitive data. Authentication, parsing, integrity, and cryptographic failures cause the operation to stop safely.

### Security auditing
The project includes unit tests, security-focused tests, malformed-input tests, static analysis, dependency vulnerability checks, and code review of security-sensitive components.

### Least privilege
The application does not require administrator privileges and does not expose a network service or plugin interface.

## Repository layout

```text
SecurePasswordManager/
├── README.md
├── SecurePasswordManager.sln
├── docs/
│   └── checkpoint1-design.md
├── src/
│   ├── PasswordManager.App/
│   │   └── UI/
│   └── PasswordManager.Core/
│       ├── UserManagement/
│       ├── Security/
│       ├── Validation/
│       ├── Vault/
│       ├── Storage/
│       └── Logging/
└── tests/
    └── PasswordManager.Core.Tests/
```

## Requirements
- Windows 10 or Windows 11
- .NET 10 SDK
- Git
- Visual Studio or another development environment with .NET and WPF support

## Build
From the repository root:

```powershell
dotnet restore
dotnet build SecurePasswordManager.sln
```

## Run

```powershell
dotnet run --project src/PasswordManager.App/PasswordManager.App.csproj
```

The solution can also be opened in Visual Studio and run using `PasswordManager.App` as the startup project.

## Tests

```powershell
dotnet test SecurePasswordManager.sln
```

## Windows executable
A self-contained Windows build can be produced with:

```powershell
dotnet publish src/PasswordManager.App/PasswordManager.App.csproj `
  -c Release `
  -r win-x64 `
  --self-contained true `
  -p:PublishSingleFile=true
```

The resulting release is intended to run as a local Windows password-manager executable without requiring any network service.

## Security rules
1. The application starts locked.
2. The master password is never stored or logged.
3. Vault credentials are never stored in plaintext on disk.
4. Cryptographic primitives are taken from established libraries.
5. Argon2id uses a unique random salt for master-password key derivation.
6. Key-derivation parameters loaded from the vault are validated before use.
7. AES-256-GCM authentication failure causes encrypted data to be rejected.
8. A fresh nonce is used for every AES-GCM encryption under the same key.
9. Cryptographic keys, salts, nonces, temporary names, and generated passwords use a cryptographically secure random-number generator.
10. The vault file is treated as untrusted input and validated before processing.
11. Decrypted credentials remain in memory only as long as required.
12. The vault is stored in a private application directory.
13. Vault saves avoid separate check-then-write file operations.
14. Sensitive vault content is never written to application logs.
15. Log messages use fixed or structured event types rather than untrusted strings as format data.
16. Logs are size-limited and rotated.
17. Authentication, parsing, and integrity failures are handled without exposing sensitive details.
18. A failed save does not replace the previous valid vault.
19. Administrator privileges are not required.
20. Dependencies and security-sensitive code are reviewed and tested before release.

## Design documentation
The architecture, threat model, initial vault format, and cryptographic scheme are described in:

[`docs/checkpoint1-design.md`](docs/checkpoint1-design.md)
