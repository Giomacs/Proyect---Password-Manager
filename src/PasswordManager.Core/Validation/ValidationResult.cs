namespace PasswordManager.Core.Validation;

/// <summary>
/// Does not contain the input value. Validation codes are safe to use in
/// an interface or tests. Never add user-entered data to error messages.
/// </summary>
public sealed record ValidationIssue(string Field, string Code);

public sealed class ValidationResult
{
    private readonly List<ValidationIssue> _issues = new();

    public bool IsValid => _issues.Count == 0;
    public IReadOnlyList<ValidationIssue> Issues => _issues.AsReadOnly();

    internal void Add(string field, string code) => _issues.Add(new ValidationIssue(field, code));
}
