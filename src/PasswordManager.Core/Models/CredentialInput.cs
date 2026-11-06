namespace PasswordManager.Core.Models;

/// <summary>
/// Transient credential data supplied by the interface. Contains a plaintext
/// password: do not persist, log, or retain beyond the operation that needs it.
/// </summary>
public sealed class CredentialInput
{
    public string? Title { get; init; }
    public string? Username { get; init; }
    public string? Password { get; init; }
    public string? Url { get; init; }
    public string? Notes { get; init; }

    // Do not allow a debugger/log interpolation to print credential properties.
    public override string ToString() => "CredentialInput (sensitive)";
}
