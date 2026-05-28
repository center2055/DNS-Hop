using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Platform;
using Avalonia.Styling;
using DNSHop.App.ViewModels;
using FluentAvalonia.UI.Controls;
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace DNSHop.App.Views;

public partial class ShellWindow : Window
{
    public ShellWindow()
    {
        InitializeComponent();
        DataContextChanged += (_, _) => HookViewModel();

        // Initialized fires once the platform window handle exists but before the
        // first frame is presented; calling DWM here avoids a white-title-bar flash.
        Initialized += (_, _) => ApplyWindowChrome();

        Opened += (_, _) =>
        {
            ApplyTheme();
            ApplyBackdrop();
            ApplyWindowChrome();
        };
        Activated += (_, _) => ApplyWindowChrome();

        var nav = this.FindControl<NavigationView>("Nav");
        if (nav is not null)
        {
            nav.ItemInvoked += OnNavItemInvoked;
        }
    }

    private void OnNavItemInvoked(object? sender, NavigationViewItemInvokedEventArgs e)
    {
        if (DataContext is not ShellViewModel shell)
        {
            return;
        }

        if (e.IsSettingsInvoked)
        {
            shell.GoTo("Settings");
        }
    }

    private void HookViewModel()
    {
        if (DataContext is ShellViewModel shell)
        {
            shell.PropertyChanged += OnShellPropertyChanged;
            ApplyTheme();
            ApplyBackdrop();
        }
    }

    private void OnShellPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (string.Equals(e.PropertyName, nameof(ShellViewModel.UseMica), StringComparison.Ordinal))
        {
            ApplyBackdrop();
        }
        else if (string.Equals(e.PropertyName, nameof(ShellViewModel.ActiveTheme), StringComparison.Ordinal))
        {
            ApplyTheme();
            ApplyBackdrop();
            ApplyWindowChrome();
        }
    }

    private void ApplyBackdrop()
    {
        if (DataContext is not ShellViewModel shell)
        {
            return;
        }

        // Mica is a system-painted backdrop and ignores the in-app theme override.
        // Only allow it when the user is letting the app follow the OS theme — otherwise
        // an explicit Light selection on a dark OS would still show a dark sidebar.
        bool micaAllowed = shell.UseMica && string.Equals(shell.ActiveTheme, "System", StringComparison.Ordinal);

        if (micaAllowed)
        {
            Background = Brushes.Transparent;
            TransparencyLevelHint = new[]
            {
                WindowTransparencyLevel.Mica,
                WindowTransparencyLevel.AcrylicBlur,
                WindowTransparencyLevel.None,
            };
        }
        else
        {
            TransparencyLevelHint = new[] { WindowTransparencyLevel.None };
            Background = IsEffectivelyDark()
                ? new SolidColorBrush(Color.FromRgb(0x20, 0x20, 0x20))
                : new SolidColorBrush(Color.FromRgb(0xF3, 0xF3, 0xF3));
        }
    }

    private void ApplyTheme()
    {
        if (DataContext is not ShellViewModel shell)
        {
            return;
        }

        var variant = shell.ActiveTheme switch
        {
            "Light" => ThemeVariant.Light,
            "Dark" => ThemeVariant.Dark,
            _ => ThemeVariant.Default,
        };

        RequestedThemeVariant = variant;

        if (Application.Current is { } app)
        {
            app.RequestedThemeVariant = variant;
        }

        if (OperatingSystem.IsWindows())
        {
            // Tell uxtheme about the new mode so any future window in this process
            // (including the FluentAvalonia ContentDialog overlay layer) paints
            // with the right chrome immediately.
            DNSHop.App.Services.WindowsAppMode.Apply(shell.ActiveTheme);
        }
    }

    private void ApplyWindowChrome()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            IntPtr? hwnd = TryGetPlatformHandle()?.Handle;
            if (hwnd is null || hwnd == IntPtr.Zero)
            {
                return;
            }

            int round = (int)DwmCornerPreference.Round;
            DwmSetWindowAttribute(hwnd.Value, DWMWA_WINDOW_CORNER_PREFERENCE, ref round, sizeof(int));

            int darkMode = IsEffectivelyDark() ? 1 : 0;
            DwmSetWindowAttribute(hwnd.Value, DWMWA_USE_IMMERSIVE_DARK_MODE, ref darkMode, sizeof(int));

            // The DWM attribute only takes effect at the next non-client paint.
            // SWP_FRAMECHANGED forces that repaint immediately so the title bar
            // never flashes light on first show.
            const uint SWP_NOSIZE = 0x0001;
            const uint SWP_NOMOVE = 0x0002;
            const uint SWP_NOZORDER = 0x0004;
            const uint SWP_NOACTIVATE = 0x0010;
            const uint SWP_FRAMECHANGED = 0x0020;
            SetWindowPos(
                hwnd.Value,
                IntPtr.Zero,
                0, 0, 0, 0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
        }
        catch
        {
        }
    }

    private bool IsEffectivelyDark()
    {
        if (DataContext is ShellViewModel shell)
        {
            if (string.Equals(shell.ActiveTheme, "Light", StringComparison.Ordinal))
            {
                return false;
            }
            if (string.Equals(shell.ActiveTheme, "Dark", StringComparison.Ordinal))
            {
                return true;
            }
        }

        var current = ActualThemeVariant ?? RequestedThemeVariant;
        if (current == ThemeVariant.Dark)
        {
            return true;
        }
        if (current == ThemeVariant.Light)
        {
            return false;
        }

        return Application.Current?.ActualThemeVariant == ThemeVariant.Dark;
    }

    private const int DWMWA_WINDOW_CORNER_PREFERENCE = 33;
    private const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20;

    private enum DwmCornerPreference
    {
        Default = 0,
        DoNotRound = 1,
        Round = 2,
        RoundSmall = 3,
    }

    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int attributeSize);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);
}
