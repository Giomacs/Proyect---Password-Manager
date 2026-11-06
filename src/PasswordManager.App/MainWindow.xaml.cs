using System.IO;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using PasswordManager.App.Controls;
using PasswordManager.App.Services;
using PasswordManager.Core.Models;
using PasswordManager.Core.UserManagement;
using PasswordManager.Core.Validation;

namespace PasswordManager.App;

/// <summary>
/// WPF presentation only. All vault access is mediated by VaultSessionManager.
/// The interface never renders a stored password as cleartext.
/// </summary>
public partial class MainWindow : Window
{
    private enum CredentialViewMode { List, Cards }
    private CredentialViewMode _credentialViewMode = CredentialViewMode.List;

    // Card width is a dependency property so WPF bindings update when the window is resized.
    public static readonly DependencyProperty EntryCardWidthProperty =
        DependencyProperty.Register(nameof(EntryCardWidth), typeof(double), typeof(MainWindow),
            new PropertyMetadata(320.0));

    public double EntryCardWidth
    {
        get => (double)GetValue(EntryCardWidthProperty);
        private set => SetValue(EntryCardWidthProperty, value);
    }

    private readonly VaultSessionManager _session;
    private readonly PasswordClipboardGuard _clipboard;
    private readonly DispatcherTimer _uiTimer;
    private IReadOnlyList<VaultEntrySummary> _entries = Array.Empty<VaultEntrySummary>();
    private CredentialEditorWindow? _activeEditor;

    public MainWindow()
    {
        InitializeComponent();
        _session = new VaultSessionManager();
        _clipboard = new PasswordClipboardGuard();
        UndoSuppression.Install(this);

        ConfigureEntryView(CredentialViewMode.List);

        _uiTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _uiTimer.Tick += UiTimer_Tick;
        Loaded += (_, _) =>
        {
            UpdateViewFromSession();
            _uiTimer.Start();
        };
    }

    protected override void OnPreviewKeyDown(KeyEventArgs e)
    {
        if (UndoSuppression.IsBlockedShortcut(e))
        {
            e.Handled = true;
            return;
        }

        RegisterActivityIfUnlocked();
        base.OnPreviewKeyDown(e);
    }

    protected override void OnPreviewMouseDown(MouseButtonEventArgs e)
    {
        RegisterActivityIfUnlocked();
        base.OnPreviewMouseDown(e);
    }

    protected override void OnClosed(EventArgs e)
    {
        _uiTimer.Stop();
        _uiTimer.Tick -= UiTimer_Tick;
        if (_activeEditor is not null)
            _activeEditor.CancelAndClose();
        _clipboard.Dispose();
        _session.Dispose();
        base.OnClosed(e);
    }

    private void UiTimer_Tick(object? sender, EventArgs e)
    {
        UpdateViewFromSession();

        // Refresh the visible countdown every second.
        UpdateAutoLockCountdown();

        if (UnlockView.Visibility == Visibility.Visible)
            UpdateRetryDisplay();
    }

    private void UpdateAutoLockCountdown()
    {
        // The timer is only visible while the vault is unlocked.
        if (!_session.IsUnlocked)
        {
            AutoLockBadge.Visibility = Visibility.Collapsed;
            return;
        }

        TimeSpan remaining = _session.TimeUntilAutoLock;

        if (remaining <= TimeSpan.Zero)
        {
            AutoLockBadge.Visibility = Visibility.Collapsed;
            UpdateViewFromSession();
            return;
        }

        // Round upward so the countdown doesn't show zero prematurely.
        int totalSeconds = (int)Math.Ceiling(remaining.TotalSeconds);

        int hours = totalSeconds / 3600;
        int minutes = (totalSeconds % 3600) / 60;
        int seconds = totalSeconds % 60;

        AutoLockCountdownText.Text = hours > 0
            ? $"{hours:00}:{minutes:00}:{seconds:00}"
            : $"{minutes:00}:{seconds:00}";

        AutoLockBadge.Visibility = Visibility.Visible;
    }

    private void RegisterActivityIfUnlocked()
    {
        // The background inactivity timer may lock the session between
        // IsUnlocked and RegisterUserActivity. Treat that as a normal lock,
        // not as an unhandled UI exception.
        try
        {
            if (_session.IsUnlocked)
                _session.RegisterUserActivity();
        }
        catch (InvalidOperationException)
        {
            UpdateViewFromSession();
        }
    }

    private void UpdateViewFromSession()
    {
        if (_session.IsUnlocked)
        {
            if (VaultView.Visibility != Visibility.Visible)
                ShowVault();
            return;
        }

        bool wasInVault = VaultView.Visibility == Visibility.Visible;
        if (wasInVault)
        {
            // The lock can happen on a background Core timer, including
            // while the modal editor is open. Clear sensitive UI state.
            _activeEditor?.CancelAndClose();
            _clipboard.ClearIfStillOwned();
            EntryList.ItemsSource = null;
            _entries = Array.Empty<VaultEntrySummary>();
            SearchBox.Clear();
            VaultStatusText.Text = string.Empty;
            UnlockMasterBox.Clear();
        }

        VaultView.Visibility = Visibility.Collapsed;
        AutoLockBadge.Visibility = Visibility.Collapsed;
        if (_session.VaultExists)
        {
            CreateView.Visibility = Visibility.Collapsed;
            if (UnlockView.Visibility != Visibility.Visible)
            {
                UnlockErrorText.Visibility = Visibility.Collapsed;
                UnlockView.Visibility = Visibility.Visible;
                UpdateRetryDisplay();
                UnlockMasterBox.Focus();
            }
        }
        else
        {
            UnlockView.Visibility = Visibility.Collapsed;
            CreateView.Visibility = Visibility.Visible;
            if (wasInVault) CreateMasterBox.Clear();
        }
    }

    private void ShowVault()
    {
        CreateMasterBox.Clear();
        ConfirmMasterBox.Clear();
        UnlockMasterBox.Clear();
        CreateErrorText.Visibility = Visibility.Collapsed;
        UnlockErrorText.Visibility = Visibility.Collapsed;
        CreateView.Visibility = Visibility.Collapsed;
        UnlockView.Visibility = Visibility.Collapsed;
        VaultView.Visibility = Visibility.Visible;
        RefreshEntries();
        UpdateAutoLockCountdown();
        SetVaultStatus("Vault unlocked. Passwords are masked and can be copied on request.");
    }

    private void CreateVault_Click(object sender, RoutedEventArgs e)
    {
        string master = CreateMasterBox.Password;
        string confirmation = ConfirmMasterBox.Password;
        CreateMasterBox.Clear();
        ConfirmMasterBox.Clear();

        if (!StringComparer.Ordinal.Equals(master, confirmation))
        {
            ShowCreateError("The master passwords do not match.");
            return;
        }
        if (!CredentialValidator.ValidateMasterPassword(master).IsValid)
        {
            ShowCreateError("Choose a master password between 12 and 1024 valid characters.");
            return;
        }

        try
        {
            _session.CreateVault(master);
            UpdateViewFromSession();
        }
        catch (Exception ex) when (IsExpectedUiError(ex))
        {
            ShowCreateError("Could not create the vault. Check permissions and available disk space.");
        }
    }

    private void UnlockVault_Click(object sender, RoutedEventArgs e)
    {
        string password = UnlockMasterBox.Password;
        UnlockMasterBox.Clear();
        try
        {
            _session.Unlock(password);
            UpdateViewFromSession();
        }
        catch (Exception ex) when (IsExpectedUiError(ex))
        {
            UnlockErrorText.Text = "Unable to unlock. The master password or vault may be invalid.";
            UnlockErrorText.Visibility = Visibility.Visible;
            UpdateRetryDisplay();
        }
    }

    private void UnlockMasterBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter && UnlockButton.IsEnabled)
        {
            e.Handled = true;
            UnlockVault_Click(sender, e);
        }
    }

    private void UpdateRetryDisplay()
    {
        TimeSpan retry = _session.UnlockRetryAfter;
        bool blocked = retry > TimeSpan.Zero;
        UnlockButton.IsEnabled = !blocked;
        RetryText.Text = blocked
            ? $"Try again in {Math.Ceiling(retry.TotalSeconds):0} second(s)."
            : string.Empty;
    }

    private void ShowCreateError(string message)
    {
        CreateErrorText.Text = message;
        CreateErrorText.Visibility = Visibility.Visible;
    }

    private void LockVault_Click(object sender, RoutedEventArgs e)
    {
        _session.Lock();
        UpdateViewFromSession();
    }

    private void TimeoutBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        // SelectedIndex is set by XAML during InitializeComponent, before
        // the Core session exists; the initial value already matches 5 min.
        if (!IsLoaded || !_session.IsUnlocked)
            return;
        if (TimeoutBox.SelectedItem is not ComboBoxItem item ||
            !int.TryParse(item.Tag?.ToString(), out int minutes))
            return;

        try
        {
            _session.SetInactivityTimeout(TimeSpan.FromMinutes(minutes));
            UpdateAutoLockCountdown();
            SetVaultStatus($"Automatic lock set to {minutes} minute(s).");
        }
        catch (Exception ex) when (IsExpectedUiError(ex))
        {
            UpdateViewFromSession();
        }
    }

    private void RefreshEntries()
    {
        try
        {
            _entries = _session.ListEntries();
            CountText.Text = _entries.Count == 1 ? "1 entry" : $"{_entries.Count} entries";
            ApplySearchFilter();
        }
        catch (Exception ex) when (IsExpectedUiError(ex))
        {
            // Never leave stale credential details visible after a read failure.
            EntryList.ItemsSource = null;
            _entries = Array.Empty<VaultEntrySummary>();
            _session.Lock();
            UpdateViewFromSession();
        }
    }

    private void ListView_Click(object sender, RoutedEventArgs e)
        => ConfigureEntryView(CredentialViewMode.List);

    private void CardsView_Click(object sender, RoutedEventArgs e)
        => ConfigureEntryView(CredentialViewMode.Cards);

    private void ConfigureEntryView(CredentialViewMode mode)
    {
        // The same ListBox is used in both modes. Selection, searching,
        // authorization checks, and password-free summaries are unchanged.
        Guid? selectedId = SelectedEntry?.Id;
        _credentialViewMode = mode;

        EntryList.ItemTemplate = (DataTemplate)FindResource(
            mode == CredentialViewMode.List ? "CredentialRowTemplate" : "CredentialCardTemplate");
        EntryList.ItemsPanel = (ItemsPanelTemplate)FindResource(
            mode == CredentialViewMode.List ? "CredentialListPanel" : "CredentialCardPanel");

        if (mode == CredentialViewMode.Cards)
            UpdateEntryCardWidth();

        if (selectedId.HasValue)
            EntryList.SelectedItem = EntryList.Items.OfType<VaultEntrySummary>()
                .FirstOrDefault(entry => entry.Id == selectedId.Value);

        // Give the active view a light green highlight.
        var activeBackground = (Brush)FindResource("AccentPaleBrush");
        var activeBorder = (Brush)FindResource("AccentBrush");
        var inactiveBorder = (Brush)FindResource("LineBrush");
        ListViewButton.Background = mode == CredentialViewMode.List ? activeBackground : Brushes.White;
        ListViewButton.BorderBrush = mode == CredentialViewMode.List ? activeBorder : inactiveBorder;
        CardsViewButton.Background = mode == CredentialViewMode.Cards ? activeBackground : Brushes.White;
        CardsViewButton.BorderBrush = mode == CredentialViewMode.Cards ? activeBorder : inactiveBorder;

        UpdateSelectionButtons();
    }

    private void EntryList_SizeChanged(object sender, SizeChangedEventArgs e)
    {
        if (_credentialViewMode == CredentialViewMode.Cards)
            UpdateEntryCardWidth();
    }

    private void UpdateEntryCardWidth()
    {
        // Reserve room for a scrollbar so cards never cause horizontal scrolling.
        double available = EntryList.ActualWidth - SystemParameters.VerticalScrollBarWidth - 12;
        if (available <= 0)
            return;

        const double minimumCardWidth = 290;
        const double cardGap = 12;
        int columns = Math.Clamp((int)Math.Floor((available + cardGap) /
                             (minimumCardWidth + cardGap)), 1, 3);
        EntryCardWidth = Math.Max(190, Math.Floor(available / columns) - cardGap - 8);
    }

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (!IsLoaded || VaultView.Visibility != Visibility.Visible)
            return;
        ApplySearchFilter();
    }

    private void ApplySearchFilter()
    {
        string query = SearchBox.Text;
        IReadOnlyList<VaultEntrySummary> visible = string.IsNullOrWhiteSpace(query)
            ? _entries
            : _entries.Where(item =>
                item.Title.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                (item.Username?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false) ||
                (item.Url?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false))
                .ToArray();

        EntryList.ItemsSource = visible;
        UpdateSelectionButtons();
    }

    private void EntryList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (IsLoaded) UpdateSelectionButtons();
    }

    private void UpdateSelectionButtons()
    {
        bool selected = EntryList.SelectedItem is VaultEntrySummary;
        EditButton.IsEnabled = selected;
        CopyButton.IsEnabled = selected;
        DeleteButton.IsEnabled = selected;
    }

    private VaultEntrySummary? SelectedEntry => EntryList.SelectedItem as VaultEntrySummary;

    private void AddEntry_Click(object sender, RoutedEventArgs e)
        => OpenEditor(null);

    private void EditEntry_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedEntry is { } entry)
            OpenEditor(entry.Id);
    }

    private void OpenEditor(Guid? editId)
    {
        if (!_session.IsUnlocked)
        {
            UpdateViewFromSession();
            return;
        }

        CredentialInput? original;
        try
        {
            original = editId.HasValue ? _session.GetCredential(editId.Value) : null;
        }
        catch (Exception ex) when (IsExpectedUiError(ex))
        {
            SetVaultStatus("Unable to open the selected credential.", isError: true);
            UpdateViewFromSession();
            return;
        }

        var editor = new CredentialEditorWindow(original, RegisterActivityIfUnlocked)
        {
            Owner = this
        };
        _activeEditor = editor;
        original = null; // Do not retain a second reference across the modal session.
        try
        {
            bool? accepted = editor.ShowDialog();
            if (accepted != true || editor.Result is not { } input)
                return;

            // The background timeout can fire while a dialog is open. The
            // Core session remains authoritative even if the UI is stale.
            if (!_session.IsUnlocked)
            {
                UpdateViewFromSession();
                return;
            }

            if (editId.HasValue)
            {
                if (!_session.UpdateCredential(editId.Value, input))
                {
                    SetVaultStatus("That entry no longer exists.", isError: true);
                    return;
                }
            }
            else
            {
                _session.AddCredential(input);
            }
            RefreshEntries();
            SetVaultStatus("Credential saved to the encrypted vault.");
        }
        catch (Exception ex) when (IsExpectedUiError(ex))
        {
            SetVaultStatus("Unable to save the credential. No change was committed.", isError: true);
            UpdateViewFromSession();
        }
        finally
        {
            editor.ForgetResult();
            _activeEditor = null;
        }
    }

    private void DeleteEntry_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedEntry is not { } entry) return;
        MessageBoxResult confirmation = MessageBox.Show(this,
            "Delete the selected credential permanently?", "Confirm deletion",
            MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
        if (confirmation != MessageBoxResult.Yes) return;

        try
        {
            if (_session.DeleteCredential(entry.Id))
            {
                RefreshEntries();
                SetVaultStatus("Credential deleted from the encrypted vault.");
            }
            else
            {
                SetVaultStatus("The selected entry no longer exists.", isError: true);
            }
        }
        catch (Exception ex) when (IsExpectedUiError(ex))
        {
            SetVaultStatus("Unable to delete the selected credential.", isError: true);
            UpdateViewFromSession();
        }
    }

    private void CopyPassword_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedEntry is not { } entry) return;
        try
        {
            CredentialInput credential = _session.GetCredential(entry.Id);
            _clipboard.CopyPassword(credential.Password ?? string.Empty);
            SetVaultStatus("Password copied. The application will try to clear it in 20 seconds.");
        }
        catch (Exception ex) when (IsExpectedUiError(ex))
        {
            SetVaultStatus("Unable to copy the password.", isError: true);
            UpdateViewFromSession();
        }
    }

    private void SetVaultStatus(string message, bool isError = false)
    {
        VaultStatusText.Text = message;
        VaultStatusText.Foreground = (Brush)FindResource(isError ? "ErrorBrush" : "MutedBrush");
    }

    private static bool IsExpectedUiError(Exception error)
        => error is CryptographicException or InvalidDataException or IOException
            or UnauthorizedAccessException or ArgumentException or InvalidOperationException
            or System.Runtime.InteropServices.ExternalException;
}
