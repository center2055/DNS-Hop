using Avalonia.Controls;
using Avalonia.Data;
using Avalonia.Layout;
using Avalonia.Markup.Xaml;
using DNSHop.App.ViewModels.Pages;
using FluentAvalonia.UI.Controls;
using System;
using System.ComponentModel;
using System.Threading.Tasks;

namespace DNSHop.App.Views.Pages;

public partial class ResolversPageView : UserControl
{
    private ResolversPageViewModel? _hookedVm;
    private ContentDialog? _activeDialog;

    public ResolversPageView()
    {
        InitializeComponent();
        DataContextChanged += (_, _) => HookViewModel();
    }

    private void HookViewModel()
    {
        if (_hookedVm is not null)
        {
            _hookedVm.PropertyChanged -= OnVmPropertyChanged;
            _hookedVm = null;
        }

        if (DataContext is ResolversPageViewModel vm)
        {
            _hookedVm = vm;
            vm.PropertyChanged += OnVmPropertyChanged;
        }
    }

    private void OnVmPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (sender is not ResolversPageViewModel vm)
        {
            return;
        }

        if (!string.Equals(e.PropertyName, nameof(ResolversPageViewModel.IsAdding), StringComparison.Ordinal))
        {
            return;
        }

        if (vm.IsAdding && _activeDialog is null)
        {
            _ = ShowDialogAsync(vm);
        }
        else if (!vm.IsAdding && _activeDialog is not null)
        {
            _activeDialog.Hide();
        }
    }

    private async Task ShowDialogAsync(ResolversPageViewModel vm)
    {
        var dialog = new ContentDialog
        {
            Title = "Add a custom DNS endpoint",
            PrimaryButtonText = "Save",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary,
            Content = BuildForm(vm),
        };

        dialog.PrimaryButtonClick += (_, args) =>
        {
            // Run the VM's validation + save synchronously. If it failed,
            // vm.IsAdding stays true and we keep the dialog open so the
            // freshly-set AddError is visible inline.
            vm.SaveCustomCommand.Execute(null);
            if (vm.IsAdding)
            {
                args.Cancel = true;
            }
        };

        _activeDialog = dialog;
        try
        {
            var result = await dialog.ShowAsync();
            if (result != ContentDialogResult.Primary)
            {
                // Close/Cancel/back arrow — always reset VM state.
                if (vm.IsAdding)
                {
                    vm.CancelAddCustomCommand.Execute(null);
                }
            }
        }
        finally
        {
            _activeDialog = null;
        }
    }

    private static StackPanel BuildForm(ResolversPageViewModel vm)
    {
        var protocolCombo = new ComboBox
        {
            ItemsSource = vm.AvailableProtocols,
            HorizontalAlignment = HorizontalAlignment.Stretch,
            MinWidth = 360,
        };
        protocolCombo.Bind(ComboBox.SelectedItemProperty, new Binding("Draft.Protocol") { Mode = BindingMode.TwoWay, Source = vm });

        var providerBox = new TextBox { Watermark = "Custom DNS" };
        providerBox.Bind(TextBox.TextProperty, new Binding("Draft.Provider") { Mode = BindingMode.TwoWay, Source = vm });

        var endpointBox = new TextBox { Watermark = "IPv4 / IPv6 (UDP/TCP, DoT) or https URL (DoH)" };
        endpointBox.Bind(TextBox.TextProperty, new Binding("Draft.Endpoint") { Mode = BindingMode.TwoWay, Source = vm });

        var portUpDown = new NumericUpDown { Minimum = 1, Maximum = 65535, Increment = 1 };
        portUpDown.Bind(NumericUpDown.ValueProperty, new Binding("Draft.Port") { Mode = BindingMode.TwoWay, Source = vm });

        var tlsHostBox = new TextBox { Watermark = "e.g. dns.quad9.net" };
        tlsHostBox.Bind(TextBox.TextProperty, new Binding("Draft.DotTlsHost") { Mode = BindingMode.TwoWay, Source = vm });

        var portTlsGrid = new Grid
        {
            ColumnDefinitions = ColumnDefinitions.Parse("*,*"),
            ColumnSpacing = 12,
        };
        var portStack = new StackPanel { Spacing = 4 };
        portStack.Children.Add(new TextBlock { Text = "Port", Classes = { "Caption" } });
        portStack.Children.Add(portUpDown);
        Grid.SetColumn(portStack, 0);

        var tlsStack = new StackPanel { Spacing = 4 };
        tlsStack.Children.Add(new TextBlock { Text = "DoT TLS host (optional)", Classes = { "Caption" } });
        tlsStack.Children.Add(tlsHostBox);
        Grid.SetColumn(tlsStack, 1);

        portTlsGrid.Children.Add(portStack);
        portTlsGrid.Children.Add(tlsStack);

        var errorText = new TextBlock
        {
            TextWrapping = Avalonia.Media.TextWrapping.Wrap,
        };
        errorText.Classes.Add("Caption");
        errorText.Bind(TextBlock.TextProperty, new Binding("AddError") { Source = vm });
        errorText.Bind(TextBlock.IsVisibleProperty, new Binding("AddError")
        {
            Source = vm,
            Converter = Avalonia.Data.Converters.StringConverters.IsNotNullOrEmpty,
        });
        if (Avalonia.Application.Current is { } app
            && app.TryGetResource("SystemFillColorCriticalBrush", null, out var brush)
            && brush is Avalonia.Media.IBrush criticalBrush)
        {
            errorText.Foreground = criticalBrush;
        }
        else
        {
            errorText.Foreground = Avalonia.Media.Brushes.Crimson;
        }

        var form = new StackPanel
        {
            Spacing = 12,
            MinWidth = 460,
        };
        AppendField(form, "Protocol", protocolCombo);
        AppendField(form, "Provider label", providerBox);
        AppendField(form, "Endpoint", endpointBox);
        form.Children.Add(portTlsGrid);
        form.Children.Add(errorText);

        return form;
    }

    private static void AppendField(StackPanel form, string label, Control input)
    {
        var stack = new StackPanel { Spacing = 4 };
        stack.Children.Add(new TextBlock { Text = label, Classes = { "Caption" } });
        stack.Children.Add(input);
        form.Children.Add(stack);
    }
}
