using System.Windows;
using System.Windows.Input;
using PasswordManager.App.Controls;
using PasswordManager.Core.Models;
using PasswordManager.Core.Validation;

namespace PasswordManager.App;

/// <summary>
/// Transient credential form. Never displays the Password as normal text.
/// TextBox undo history and Ctrl+Z/Ctrl+Y are disabled.
/// </summary>
public partial class CredentialEditorWindow : Window
{
    private readonly Action _userActivity;

    public CredentialInput? Result { get; private set; }

    public CredentialEditorWindow(CredentialInput? existing, Action userActivity)
    {
        InitializeComponent();
        _userActivity = userActivity ?? throw new ArgumentNullException(nameof(userActivity));
        UndoSuppression.Install(this);
        Loaded += (_, _) => TitleField.Focus();

        if (existing is not null)
        {
            EditorHeading.Text = "Edit credential";
            TitleField.Text = existing.Title ?? string.Empty;
            UsernameField.Text = existing.Username ?? string.Empty;
            SecretField.Password = existing.Password ?? string.Empty;
            UrlField.Text = existing.Url ?? string.Empty;
            NotesField.Text = existing.Notes ?? string.Empty;
        }
        else
        {
            EditorHeading.Text = "Add credential";
        }
    }

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        var input = new CredentialInput
        {
            Title = TitleField.Text,
            Username = UsernameField.Text,
            Password = SecretField.Password,
            Url = UrlField.Text,
            Notes = NotesField.Text
        };

        ValidationResult validation = CredentialValidator.Validate(input);
        if (!validation.IsValid)
        {
            EditorErrorText.Text = "Check the required title and password, and remove any invalid characters.";
            EditorErrorText.Visibility = Visibility.Visible;
            return;
        }

        Result = input;
        DialogResult = true;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        Result = null;
        DialogResult = false;
    }

    public void CancelAndClose()
    {
        if (!IsVisible) return;
        Result = null;
        // Not a successful save; the caller will discard this dialog.
        DialogResult = false;
    }

    public void ForgetResult() => Result = null;

    protected override void OnPreviewKeyDown(KeyEventArgs e)
    {
        if (UndoSuppression.IsBlockedShortcut(e))
        {
            e.Handled = true;
            return;
        }
        _userActivity();
        base.OnPreviewKeyDown(e);
    }

    protected override void OnPreviewMouseDown(MouseButtonEventArgs e)
    {
        _userActivity();
        base.OnPreviewMouseDown(e);
    }

    protected override void OnClosed(EventArgs e)
    {
        // Managed copies of credentials cannot be guaranteed zeroed, but
        // the controls should not keep holding the entered secret.
        SecretField.Clear();
        TitleField.Clear();
        UsernameField.Clear();
        UrlField.Clear();
        NotesField.Clear();
        base.OnClosed(e);
    }
}
