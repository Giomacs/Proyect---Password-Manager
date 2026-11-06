using System.Text.Json.Serialization;

namespace PasswordManager.Core.Models;

/// <summary>
/// Untrusted, encrypted version-1 vault file structure. The fields in this
/// document are metadata or encrypted bytes encoded as Base64. Plaintext
/// credentials must never be placed in these types.
/// </summary>
public sealed class VaultFileDocument
{
    [JsonPropertyName("magic")]
    public string? Magic { get; set; }

    [JsonPropertyName("formatVersion")]
    public int FormatVersion { get; set; }

    [JsonPropertyName("kdf")]
    public VaultKdfParameters? Kdf { get; set; }

    [JsonPropertyName("wrappedVaultKey")]
    public VaultEncryptedBlob? WrappedVaultKey { get; set; }

    [JsonPropertyName("index")]
    public VaultEncryptedBlob? Index { get; set; }

    [JsonPropertyName("records")]
    public List<VaultEncryptedRecord>? Records { get; set; }
}

public sealed class VaultKdfParameters
{
    [JsonPropertyName("salt")]
    public string? Salt { get; set; }

    [JsonPropertyName("memoryKiB")]
    public int MemoryKiB { get; set; }

    [JsonPropertyName("iterations")]
    public int Iterations { get; set; }

    [JsonPropertyName("parallelism")]
    public int Parallelism { get; set; }
}

public class VaultEncryptedBlob
{
    [JsonPropertyName("nonce")]
    public string? Nonce { get; set; }

    [JsonPropertyName("ciphertext")]
    public string? Ciphertext { get; set; }

    [JsonPropertyName("tag")]
    public string? Tag { get; set; }
}

public sealed class VaultEncryptedRecord : VaultEncryptedBlob
{
    [JsonPropertyName("id")]
    public string? Id { get; set; }
}
