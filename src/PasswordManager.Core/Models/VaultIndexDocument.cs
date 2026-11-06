using System.Text.Json.Serialization;

namespace PasswordManager.Core.Models;

/// <summary>
/// Decrypted only after the vault key has been authenticated. Never saved
/// as plaintext: it is serialized and encrypted as the vault's index blob.
/// </summary>
public sealed class VaultIndexDocument
{
    [JsonPropertyName("formatVersion")]
    public int FormatVersion { get; set; } = 1;

    [JsonPropertyName("entries")]
    public List<VaultIndexEntry>? Entries { get; set; } = new();
}

public sealed class VaultIndexEntry
{
    [JsonPropertyName("id")]
    public string? Id { get; set; }

    [JsonPropertyName("title")]
    public string? Title { get; set; }

    [JsonPropertyName("username")]
    public string? Username { get; set; }

    // SHA-256 over canonical ID + nonce + ciphertext + tag.
    // This hash is stored inside the authenticated ENCRYPTED index.
    [JsonPropertyName("ciphertextSha256")]
    public string? CiphertextSha256 { get; set; }
}

public sealed record VaultEntrySummary(Guid Id, string Title, string? Username);
