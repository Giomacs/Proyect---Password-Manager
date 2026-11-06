using System.Runtime.CompilerServices;

// Allows automated storage tests to use an isolated temporary directory.
// Production callers use the fixed per-user application directory.
[assembly: InternalsVisibleTo("PasswordManager.Core.Tests")]
