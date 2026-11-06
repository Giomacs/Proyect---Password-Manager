using System.Text.Json;
using System.Text.Json.Serialization;

namespace PasswordManager.Core.Storage;

/// <summary>Strict parsing for the untrusted vault, index and record JSON.</summary>
internal static class StrictVaultJson
{
    private static readonly JsonSerializerOptions Options = new()
    {
        AllowDuplicateProperties = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        PropertyNameCaseInsensitive = false,
        MaxDepth = 16,
        WriteIndented = false
    };

    public static byte[] Serialize<T>(T value) => JsonSerializer.SerializeToUtf8Bytes(value, Options);

    public static T Deserialize<T>(ReadOnlySpan<byte> json) where T : class
    {
        try
        {
            // Parsing only a bounded buffer is mandatory; callers cap sizes first.
            T? result = JsonSerializer.Deserialize<T>(json, Options);
            return result ?? throw new InvalidDataException("Invalid vault data.");
        }
        catch (JsonException)
        {
            throw new InvalidDataException("Invalid vault data.");
        }
    }
}
