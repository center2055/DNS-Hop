using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
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

        // Extended client area kills the OS-provided drag region. Add it back:
        // any unhandled click in the top ~32px of the window starts a window drag,
        // any double-click toggles maximize/restore. Children that handle the
        // pointer (hamburger menu, etc.) still get their click because OnPointerPressed
        // on the window only fires for unhandled bubbled events.
        AddHandler(PointerPressedEvent, OnTitleBarPointerPressed, RoutingStrategies.Bubble, handledEventsToo: false);

        var nav = this.FindControl<NavigationView>("Nav");
        if (nav is not null)
        {
            nav.ItemInvoked += OnNavItemInvoked;
        }
    }

    private void OnTitleBarPointerPressed(object? sender, PointerPressedEventArgs e)
    {
        if (e.Handled)
        {
            return;
        }

        var point = e.GetCurrentPoint(this);
        if (!point.Properties.IsLeftButtonPressed)
        {
            return;
        }

        if (point.Position.Y > 36)
        {
            return;
        }

        if (e.ClickCount == 2)
        {
            WindowState = WindowState == WindowState.Maximized
                ? WindowState.Normal
                : WindowState.Maximized;
            e.Handled = true;
            return;
        }

        BeginMoveDrag(e);
        e.Handled = true;
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

    private bool _chromeApplied;
    private bool? _lastChromeDark;

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

            bool dark = IsEffectivelyDark();
            int darkMode = dark ? 1 : 0;
            DwmSetWindowAttribute(hwnd.Value, DWMWA_USE_IMMERSIVE_DARK_MODE, ref darkMode, sizeof(int));

            // Belt-and-suspenders: if some upstream theme code keeps flipping
            // IMMERSIVE_DARK_MODE back to 0, hard-set the caption colour to a
            // matching neutral shade. COLORREF is 0x00BBGGRR.
            int captionColor = dark ? 0x00202020 : unchecked((int)0xFFFFFFFE); // FFFFFFFE = "default"
            int textColor = dark ? 0x00F0F0F0 : unchecked((int)0xFFFFFFFE);
            DwmSetWindowAttribute(hwnd.Value, DWMWA_CAPTION_COLOR, ref captionColor, sizeof(int));
            DwmSetWindowAttribute(hwnd.Value, DWMWA_TEXT_COLOR, ref textColor, sizeof(int));

            // Only force the non-client repaint when something actually changed
            // (first show or a theme/dark-state flip). The DWM attributes above are
            // idempotent, so re-applying them on every window Activated is harmless,
            // but firing SWP_FRAMECHANGED on each focus-regain triggers a full
            // re-layout that clamps virtualized lists back to the top — which reset
            // the Resolvers/Results scroll position whenever the user alt-tabbed away.
            bool changed = !_chromeApplied || _lastChromeDark != dark;
            _chromeApplied = true;
            _lastChromeDark = dark;
            if (!changed)
            {
                return;
            }

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
    private const int DWMWA_CAPTION_COLOR = 35;
    private const int DWMWA_TEXT_COLOR = 36;

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
