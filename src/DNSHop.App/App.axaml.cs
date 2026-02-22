using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Data.Core;
using Avalonia.Data.Core.Plugins;
using Avalonia.Markup.Xaml;
using DNSHop.App.Services;
using DNSHop.App.ViewModels;
using DNSHop.App.Views;
using System.Linq;

namespace DNSHop.App;

public partial class App : Application
{
    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
    }

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            // CommunityToolkit and Avalonia can both validate DataAnnotations; we keep one source.
            DisableAvaloniaDataAnnotationValidation();

            var benchmarkService = new DnsBenchmarkService();
            var serverListService = new DnsServerListService();
            var recommendationService = new RecommendationService();
            var exportService = new ExportService();
            var appSettingsService = new AppSettingsService();

            desktop.MainWindow = new MainWindow
            {
                DataContext = new MainWindowViewModel(
                    benchmarkService,
                    serverListService,
                    recommendationService,
                    exportService,
                    appSettingsService),
            };
        }

        base.OnFrameworkInitializationCompleted();
    }

    private static void DisableAvaloniaDataAnnotationValidation()
    {
        var pluginsToRemove = BindingPlugins.DataValidators
            .OfType<DataAnnotationsValidationPlugin>()
            .ToArray();

        foreach (var plugin in pluginsToRemove)
        {
            BindingPlugins.DataValidators.Remove(plugin);
        }
    }
}

