using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.VisualTree;
using DNSHop.App.ViewModels;

namespace DNSHop.App.Views;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        ApplyOpaqueWindowSettings();
        DataContextChanged += (_, _) => ReapplyThemeFromViewModel();
        Opened += (_, _) =>
        {
            ApplyOpaqueWindowSettings();
            ReapplyThemeFromViewModel();
        };
        Activated += (_, _) => ReapplyThemeFromViewModel();
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
}

