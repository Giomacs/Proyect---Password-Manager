using System.Security.Cryptography;
using System.Text;
using PasswordManager.Core.Models;

namespace PasswordManager.Core.Storage;

internal static class RecordIntegrity
{
    /// <summary>
    /// Hash over unambiguous ASCII fields. The hash lives INSIDE the
    /// encrypted/authenticated index; a standalone hash would not prove integrity.
    /// </summary>
    public static string Fingerprint(VaultEncryptedRecord record)
    {
        if (record.Id is null || record.Nonce is null ||
            record.Ciphertext is null || record.Tag is null)
            throw new InvalidDataException("Invalid encrypted record.");

        string text = record.Id + "\n" + record.Nonce + "\n" +
                      record.Ciphertext + "\n" + record.Tag;
        byte[] buffer = Encoding.ASCII.GetBytes(text);
        try
        {
            return Convert.ToHexString(SHA256.HashData(buffer));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }
}
