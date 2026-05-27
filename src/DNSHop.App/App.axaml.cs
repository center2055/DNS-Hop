using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Data.Core.Plugins;
using Avalonia.Markup.Xaml;
using DNSHop.App.Localization;
using DNSHop.App.Services;
using DNSHop.App.ViewModels;
using DNSHop.App.Views;
using System.Linq;
using System.Threading.Tasks;

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
            DisableAvaloniaDataAnnotationValidation();

            var services = BuildServices();
            var shell = new ShellViewModel(services);

            RequestedThemeVariant = shell.ActiveTheme switch
            {
                "Light" => Avalonia.Styling.ThemeVariant.Light,
                "Dark" => Avalonia.Styling.ThemeVariant.Dark,
                _ => Avalonia.Styling.ThemeVariant.Default,
            };

            var window = new ShellWindow
            {
                DataContext = shell,
            };

            window.Closing += (_, _) =>
            {
                Task.Run(shell.PersistAll);
            };

            desktop.MainWindow = window;
        }

        base.OnFrameworkInitializationCompleted();
    }

    private static AppServices BuildServices()
    {
        var settingsService = new AppSettingsService();
        var settings = settingsService.Load();

        var localization = LocalizationService.Instance;
        localization.EnsureLoaded();
        var culture = string.IsNullOrWhiteSpace(settings.Language)
            ? LocalizationService.DetectSystemCulture()
            : settings.Language;
        localization.SetCulture(culture);

        var metadata = new ResolverMetadataService();
        metadata.Load();

        var appState = new AppStateService
        {
            ActiveProfileId = settings.ActiveProfileId,
        };
        foreach (var profile in settings.Profiles)
        {
            appState.Profiles.Add(profile);
        }
        foreach (var entry in settings.ApplyHistory)
        {
            appState.ApplyHistory.Add(entry);
        }

        return new AppServices
        {
            Localization = localization,
            Settings = settingsService,
            Benchmark = new DnsBenchmarkService(),
            ServerList = new DnsServerListService(),
            Recommendations = new RecommendationService(),
            Export = new ExportService(),
            Releases = new AppReleaseService(),
            SystemDns = new SystemDnsSwitchService(),
            CurrentDns = new CurrentDnsStatusService(),
            Profiles = new DnsProfileService(),
            Metadata = metadata,
            Geo = new GeoLocationService(),
            LeakTest = new DnsLeakTestService(),
            AppState = appState,
        };
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
