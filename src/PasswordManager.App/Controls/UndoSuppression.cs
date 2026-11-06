using System.Windows;
using System.Windows.Input;

namespace PasswordManager.App.Controls;

/// <summary>
/// Removes undo/redo commands from the application's WPF windows. WPF TextBox
/// undo buffers are separately disabled by the global App.xaml TextBox style.
/// This is a UI guard, not an alternative to encrypted, atomic vault saving.
/// </summary>
internal static class UndoSuppression
{
    public static void Install(Window window)
    {
        window.CommandBindings.Add(new CommandBinding(
            ApplicationCommands.Undo, BlockExecuted, BlockCanExecute));
        window.CommandBindings.Add(new CommandBinding(
            ApplicationCommands.Redo, BlockExecuted, BlockCanExecute));
    }

    public static bool IsBlockedShortcut(KeyEventArgs e)
    {
        ModifierKeys modifiers = Keyboard.Modifiers;
        return (modifiers & ModifierKeys.Control) != 0 &&
               (e.Key is Key.Z or Key.Y);
    }

    private static void BlockCanExecute(object sender, CanExecuteRoutedEventArgs e)
    {
        e.CanExecute = false;
        e.Handled = true;
    }

    private static void BlockExecuted(object sender, ExecutedRoutedEventArgs e)
        => e.Handled = true;
}
