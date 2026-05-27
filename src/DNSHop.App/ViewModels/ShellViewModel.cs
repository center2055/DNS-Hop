using CommunityToolkit.Mvvm.ComponentModel;
using DNSHop.App.Localization;
using DNSHop.App.Services;
using DNSHop.App.ViewModels.Pages;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;

namespace DNSHop.App.ViewModels;

internal sealed partial class ShellViewModel : ViewModelBase, INavigator
{
    private readonly AppServices _services;

    [ObservableProperty]
    private NavSection? _selectedSection;

    [ObservableProperty]
    private PageViewModel? _currentPage;

    [ObservableProperty]
    private bool _useMica;

    [ObservableProperty]
    private string _activeTheme = "System";

    public ShellViewModel(AppServices services)
    {
        _services = services;
        services.Navigator = this;
        Localization = services.Localization;

        HomePage = new HomePageViewModel(services);
        BenchmarkPage = new BenchmarkPageViewModel(services);
        ResolversPage = new ResolversPageViewModel(services);
        ResultsPage = new ResultsPageViewModel(services);
        ProfilesPage = new ProfilesPageViewModel(services);
        NetworkPage = new NetworkPageViewModel(services);
        LogsPage = new LogsPageViewModel(services);
        SettingsPage = new SettingsPageViewModel(services, this);
        AboutPage = new AboutPageViewModel(services);

        Sections =
        [
            new NavSection("Home", "Shell.Nav.Home", "", HomePage),
            new NavSection("Benchmark", "Shell.Nav.Benchmark", "", BenchmarkPage),
            new NavSection("Resolvers", "Shell.Nav.Resolvers", "", ResolversPage),
            new NavSection("Results", "Shell.Nav.Results", "", ResultsPage),
            new NavSection("Profiles", "Shell.Nav.Profiles", "", ProfilesPage),
            new NavSection("Network", "Shell.Nav.Network", "", NetworkPage),
            new NavSection("Logs", "Shell.Nav.Logs", "", LogsPage),
            new NavSection("About", "Shell.Nav.About", "", AboutPage),
        ];

        SettingsSection = new NavSection("Settings", "Shell.Nav.Settings", "", SettingsPage);

        var loaded = services.Settings.Load();
        _useMica = loaded.UseMica;
        _activeTheme = loaded.Theme;

        var initial = Sections.FirstOrDefault(s => s.Key == loaded.LastNavSection) ?? Sections[0];
        SelectedSection = initial;
    }

    public ILocalizationService Localization { get; }

    public HomePageViewModel HomePage { get; }
    public BenchmarkPageViewModel BenchmarkPage { get; }
    public ResolversPageViewModel ResolversPage { get; }
    public ResultsPageViewModel ResultsPage { get; }
    public ProfilesPageViewModel ProfilesPage { get; }
    public NetworkPageViewModel NetworkPage { get; }
    public LogsPageViewModel LogsPage { get; }
    public SettingsPageViewModel SettingsPage { get; }
    public AboutPageViewModel AboutPage { get; }

    public ObservableCollection<NavSection> Sections { get; }

    public NavSection SettingsSection { get; }

    public IReadOnlyList<PageViewModel> AllPages =>
        [HomePage, BenchmarkPage, ResolversPage, ResultsPage, ProfilesPage, NetworkPage, LogsPage, SettingsPage, AboutPage];

    partial void OnSelectedSectionChanged(NavSection? value)
    {
        if (value is null)
        {
            return;
        }

        if (CurrentPage is { } previous)
        {
            previous.OnDeactivated();
        }

        CurrentPage = value.ViewModel;
        value.ViewModel.OnActivated();
        PersistNavSection(value.Key);
    }

    public void GoTo(string navKey)
    {
        if (string.Equals(navKey, SettingsSection.Key, System.StringComparison.Ordinal))
        {
            SelectedSection = SettingsSection;
            return;
        }

        var match = Sections.FirstOrDefault(s => s.Key == navKey);
        if (match is not null)
        {
            SelectedSection = match;
        }
    }

    void INavigator.NavigateTo(string navKey) => GoTo(navKey);

    public void PersistAll()
    {
        var current = _services.Settings.Load();
        var profiles = _services.AppState.Profiles.ToArray();
        var history = _services.AppState.ApplyHistory.ToArray();
        var next = new AppSettings
        {
            Theme = current.Theme,
            Language = current.Language,
            UseMica = UseMica,
            LastNavSection = SelectedSection?.Key ?? current.LastNavSection,
            TimeoutMilliseconds = current.TimeoutMilliseconds,
            ConcurrencyLimit = current.ConcurrencyLimit,
            AttemptsPerProbe = current.AttemptsPerProbe,
            AutoUpdateListOnStartup = current.AutoUpdateListOnStartup,
            CheckForAppUpdatesOnStartup = current.CheckForAppUpdatesOnStartup,
            OutboundProxyType = current.OutboundProxyType,
            OutboundProxyHost = current.OutboundProxyHost,
            OutboundProxyPort = current.OutboundProxyPort,
            CustomServers = current.CustomServers,
            ActiveProfileId = _services.AppState.ActiveProfileId,
            Profiles = profiles,
            ApplyHistory = history,
        };
        _services.Settings.Save(next);
    }

    private void PersistNavSection(string key)
    {
        var current = _services.Settings.Load();
        var next = new AppSettings
        {
            Theme = current.Theme,
            Language = current.Language,
            UseMica = current.UseMica,
            LastNavSection = key,
            TimeoutMilliseconds = current.TimeoutMilliseconds,
            ConcurrencyLimit = current.ConcurrencyLimit,
            AttemptsPerProbe = current.AttemptsPerProbe,
            AutoUpdateListOnStartup = current.AutoUpdateListOnStartup,
            CheckForAppUpdatesOnStartup = current.CheckForAppUpdatesOnStartup,
            OutboundProxyType = current.OutboundProxyType,
            OutboundProxyHost = current.OutboundProxyHost,
            OutboundProxyPort = current.OutboundProxyPort,
            CustomServers = current.CustomServers,
            ActiveProfileId = current.ActiveProfileId,
            Profiles = current.Profiles,
            ApplyHistory = current.ApplyHistory,
        };
        _services.Settings.Save(next);
    }
}

internal sealed partial class NavSection : ObservableObject
{
    public NavSection(string key, string labelKey, string glyph, PageViewModel viewModel)
    {
        Key = key;
        LabelKey = labelKey;
        Glyph = glyph;
        ViewModel = viewModel;
        Localization = LocalizationService.Instance;
        Localization.PropertyChanged += (_, _) => OnPropertyChanged(nameof(Label));
    }

    public string Key { get; }

    public string LabelKey { get; }

    public string Glyph { get; }

    public PageViewModel ViewModel { get; }

    public ILocalizationService Localization { get; }

    public string Label => Localization[LabelKey];
}
