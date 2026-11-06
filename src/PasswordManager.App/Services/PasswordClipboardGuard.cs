using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Threading;

namespace PasswordManager.App.Services;

/// <summary>
/// Copies one password on explicit request, then attempts to clear it after
/// 20 seconds (or on lock). Never caches the plaintext string for a timer.
/// An ephemeral HMAC verifies that clipboard content still matches what this
/// application copied. Windows clipboard history and other clipboard readers
/// cannot be controlled by a desktop application.
/// </summary>
internal sealed class PasswordClipboardGuard : IDisposable
{
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(20) };
    private byte[]? _key;
    private byte[]? _expectedHmac;
    private bool _disposed;

    public PasswordClipboardGuard()
    {
        _timer.Tick += OnElapsed;
    }

    public void CopyPassword(string password)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (string.IsNullOrEmpty(password))
            throw new ArgumentException("A password is required.", nameof(password));

        // Do not record the password anywhere else. SetText is called from
        // the WPF UI's STA thread.
        Clipboard.SetText(password);
        ForgetFingerprint();

        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] plain = Encoding.UTF8.GetBytes(password);
        try
        {
            _key = key;
            _expectedHmac = HMACSHA256.HashData(key, plain);
            _timer.Start();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    public void ClearIfStillOwned()
    {
        _timer.Stop();
        try
        {
            if (_key is null || _expectedHmac is null || !Clipboard.ContainsText())
                return;
            string current = Clipboard.GetText();
            byte[] raw = Encoding.UTF8.GetBytes(current);
            try
            {
                byte[] currentHmac = HMACSHA256.HashData(_key, raw);
                try
                {
                    if (CryptographicOperations.FixedTimeEquals(currentHmac, _expectedHmac))
                        Clipboard.Clear();
                }
                finally { CryptographicOperations.ZeroMemory(currentHmac); }
            }
            finally { CryptographicOperations.ZeroMemory(raw); }
        }
        catch (ExternalException)
        {
            // Clipboard is temporarily owned by another process. No retries
            // that could accidentally overwrite unrelated clipboard contents.
        }
        finally
        {
            ForgetFingerprint();
        }
    }

    private void OnElapsed(object? sender, EventArgs e) => ClearIfStillOwned();

    private void ForgetFingerprint()
    {
        _timer.Stop();
        if (_key is not null) CryptographicOperations.ZeroMemory(_key);
        if (_expectedHmac is not null) CryptographicOperations.ZeroMemory(_expectedHmac);
        _key = null;
        _expectedHmac = null;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        ClearIfStillOwned();
        _timer.Tick -= OnElapsed;
    }
}
