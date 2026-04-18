using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Platform;
using Avalonia.VisualTree;
using DNSHop.App.ViewModels;
using System;
using System.Runtime.InteropServices;

namespace DNSHop.App.Views;

public partial class MainWindow : Window
{
    private const int DWMWA_WINDOW_CORNER_PREFERENCE = 33;
    private const int DWMWA_BORDER_COLOR = 34;
    private const uint DwmColorNone = 0xFFFFFFFE;

    public MainWindow()
    {
        InitializeComponent();
        ApplyOpaqueWindowSettings();
        DataContextChanged += (_, _) => ReapplyThemeFromViewModel();
        ActualThemeVariantChanged += (_, _) => ApplyNativeWindowChrome();
        Opened += (_, _) =>
        {
            ApplyOpaqueWindowSettings();
            ApplyNativeWindowChrome();
            ReapplyThemeFromViewModel();
        };
        Activated += (_, _) =>
        {
            ApplyNativeWindowChrome();
            ReapplyThemeFromViewModel();
        };
        Closing += (_, _) =>
        {
            if (DataContext is MainWindowViewModel vm)
            {
                vm.PersistSettings();
            }
        };
    }

    private void ApplyOpaqueWindowSettings()
    {
        // Force fully-opaque native window behavior to avoid translucent desktop bleed-through.
        SystemDecorations = SystemDecorations.Full;
        ExtendClientAreaToDecorationsHint = false;
        TransparencyLevelHint = [WindowTransparencyLevel.None];
        Opacity = 1.0;
    }

    private void ApplyNativeWindowChrome()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        IntPtr? hwnd = TryGetPlatformHandle()?.Handle;
        if (hwnd is null || hwnd == IntPtr.Zero)
        {
            return;
        }

        int cornerPreference = (int)DwmWindowCornerPreference.DoNotRound;
        DwmSetWindowAttribute(hwnd.Value, DWMWA_WINDOW_CORNER_PREFERENCE, ref cornerPreference, sizeof(int));

        uint borderColor = DwmColorNone;
        DwmSetWindowAttribute(hwnd.Value, DWMWA_BORDER_COLOR, ref borderColor, sizeof(uint));
    }

    private void ReapplyThemeFromViewModel()
    {
        if (DataContext is MainWindowViewModel vm)
        {
            vm.ReapplyTheme();
        }
    }

    private void NameserverGrid_OnPointerPressed(object? sender, PointerPressedEventArgs e)
    {
        if (sender is not DataGrid grid)
        {
            return;
        }

        var properties = e.GetCurrentPoint(grid).Properties;

        // Keep row actions deterministic for both normal selection (left-click)
        // and context menu actions (right-click).
        if (!properties.IsLeftButtonPressed && !properties.IsRightButtonPressed)
        {
            return;
        }

        if (e.Source is not Control sourceControl)
        {
            return;
        }

        var row = sourceControl.FindAncestorOfType<DataGridRow>();

        if (row?.DataContext is DnsServerResultViewModel rowViewModel)
        {
            grid.SelectedItem = rowViewModel;
        }
    }

    private void AddCustomDnsOverlay_OnPointerPressed(object? sender, PointerPressedEventArgs e)
    {
        if (DataContext is not MainWindowViewModel vm)
        {
            return;
        }

        if (vm.CancelAddCustomDnsCommand.CanExecute(null))
        {
            vm.CancelAddCustomDnsCommand.Execute(null);
            e.Handled = true;
        }
    }

    private void UpdatePromptOverlay_OnPointerPressed(object? sender, PointerPressedEventArgs e)
    {
        if (DataContext is not MainWindowViewModel vm)
        {
            return;
        }

        if (vm.DismissUpdatePromptCommand.CanExecute(null))
        {
            vm.DismissUpdatePromptCommand.Execute(null);
            e.Handled = true;
        }
    }

    private static void DialogSurface_OnPointerPressed(object? sender, PointerPressedEventArgs e)
    {
        e.Handled = true;
    }

    private enum DwmWindowCornerPreference
    {
        Default = 0,
        DoNotRound = 1,
        Round = 2,
        RoundSmall = 3,
    }

    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmSetWindowAttribute(
        IntPtr hwnd,
        int attribute,
        ref int value,
        int attributeSize);

    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmSetWindowAttribute(
        IntPtr hwnd,
        int attribute,
        ref uint value,
        int attributeSize);
}

