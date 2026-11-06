using PasswordManager.Core.Models;

namespace PasswordManager.Core.Validation;

/// <summary>Validation only. No logging, persistence, or password transformation.</summary>
public static class CredentialValidator
{
    public static ValidationResult Validate(CredentialInput? input)
    {
        var result = new ValidationResult();
        if (input is null)
        {
            result.Add("credential", "required");
            return result;
        }

        ValidateText(result, "title", input.Title, 1, ValidationLimits.TitleMaxChars, required: true);
        ValidateText(result, "username", input.Username, 0, ValidationLimits.UsernameMaxChars);
        ValidateText(result, "url", input.Url, 0, ValidationLimits.UrlMaxChars);
        ValidateText(result, "notes", input.Notes, 0, ValidationLimits.NotesMaxChars, multiline: true);
        ValidateSecret(result, "password", input.Password, 1,
            ValidationLimits.CredentialPasswordMaxChars);
        return result;
    }

    public static ValidationResult ValidateMasterPassword(string? password)
    {
        var result = new ValidationResult();
        ValidateSecret(result, "masterPassword", password,
            ValidationLimits.MasterPasswordMinChars,
            ValidationLimits.MasterPasswordMaxChars);
        return result;
    }

    private static void ValidateText(
        ValidationResult result, string field, string? text,
        int minLength, int maxLength, bool required = false, bool multiline = false)
    {
        // An omitted optional field is treated as an empty field later on.
        if (text is null)
        {
            if (required) result.Add(field, "required");
            return;
        }
        if (text.Length < minLength || (required && string.IsNullOrWhiteSpace(text)))
            result.Add(field, "required");
        if (text.Length > maxLength)
            result.Add(field, "too_long");
        if (!HasValidUtf16(text) || HasForbiddenControls(text, multiline))
            result.Add(field, "invalid_characters");
    }

    private static void ValidateSecret(
        ValidationResult result, string field, string? value, int minLength, int maxLength)
    {
        if (value is null || value.Length < minLength)
            result.Add(field, "too_short");
        if (value is not null)
        {
            if (value.Length > maxLength) result.Add(field, "too_long");
            if (!HasValidUtf16(value)) result.Add(field, "invalid_characters");
        }
        // Deliberately no Trim(), case-folding, normalization, or rejection
        // of whitespace: changing a password's characters changes the secret.
    }

    private static bool HasForbiddenControls(string value, bool multiline)
    {
        foreach (char ch in value)
        {
            if (!char.IsControl(ch)) continue;
            if (multiline && (ch is '\r' or '\n' or '\t')) continue;
            return true;
        }
        return false;
    }

    private static bool HasValidUtf16(string value)
    {
        for (int i = 0; i < value.Length; i++)
        {
            char ch = value[i];
            if (char.IsHighSurrogate(ch))
            {
                if (i + 1 >= value.Length || !char.IsLowSurrogate(value[i + 1]))
                    return false;
                i++; // The low surrogate belongs to this pair.
            }
            else if (char.IsLowSurrogate(ch))
            {
                return false;
            }
        }
        return true;
    }
}
