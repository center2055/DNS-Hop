using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DNSHop.App.Localization;
using DNSHop.App.Services;
using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DNSHop.App.ViewModels.Pages;

internal sealed partial class SettingsPageViewModel : PageViewModel
{
    private readonly AppServices _services;
    private readonly ShellViewModel _shell;
    private bool _suppressPersist;

    [ObservableProperty]
    private string _selectedTheme = "System";

    [ObservableProperty]
    private LanguageDescriptor? _selectedLanguage;

    [ObservableProperty]
    private bool _useMica;

    [ObservableProperty]
    private bool _checkForAppUpdatesOnStartup;

    [ObservableProperty]
    private string _outboundProxyType = "None";

    [ObservableProperty]
    private string _outboundProxyHost = string.Empty;

    [ObservableProperty]
    private int _outboundProxyPort = 1080;

    [ObservableProperty]
    private string _updateStatus = string.Empty;

    public SettingsPageViewModel(AppServices services, ShellViewModel shell) : base("Settings", "Settings.Title")
    {
        _services = services;
        _shell = shell;

        AvailableThemes = new ObservableCollection<string> { "System", "Light", "Dark" };
        AvailableLanguages = new ObservableCollection<LanguageDescriptor>(_services.Localization.AvailableLanguages);
        AvailableProxyTypes = new ObservableCollection<string> { "None", "Https", "Socks4", "Socks5" };

        var settings = _services.Settings.Load();
        _suppressPersist = true;
        SelectedTheme = settings.Theme;
        SelectedLanguage = AvailableLanguages.FirstOrDefault(l => string.Equals(l.Culture, string.IsNullOrEmpty(settings.Language) ? LocalizationService.DetectSystemCulture() : settings.Language, StringComparison.OrdinalIgnoreCase))
                          ?? AvailableLanguages.First();
        UseMica = settings.UseMica;
        CheckForAppUpdatesOnStartup = settings.CheckForAppUpdatesOnStartup;
        OutboundProxyType = settings.OutboundProxyType;
        OutboundProxyHost = settings.OutboundProxyHost;
        OutboundProxyPort = settings.OutboundProxyPort;
        _suppressPersist = false;
    }

    public ObservableCollection<string> AvailableThemes { get; }

    public ObservableCollection<LanguageDescriptor> AvailableLanguages { get; }

    public ObservableCollection<string> AvailableProxyTypes { get; }

    [RelayCommand]
    private async Task CheckForUpdatesAsync()
    {
        UpdateStatus = Localization["Common.Loading"];
        try
        {
            var snapshot = await _services.Releases.GetReleaseSnapshotAsync(CancellationToken.None).ConfigureAwait(false);
            var latest = snapshot.LatestStableRelease;
            if (latest?.ParsedVersion is null)
            {
                UpdateStatus = "—";
                return;
            }

            UpdateStatus = latest.ParsedVersion > _services.Releases.CurrentVersion
                ? string.Format(Localization["Home.Update.Available"], latest.ParsedVersion.ToString(3))
                : _services.Releases.CurrentVersionText;
        }
        catch (Exception ex)
        {
            UpdateStatus = ex.Message;
        }
    }

    partial void OnSelectedThemeChanged(string value)
    {
        _shell.ActiveTheme = value;
        Persist();
    }

    partial void OnSelectedLanguageChanged(LanguageDescriptor? value)
    {
        if (value is not null)
        {
            _services.Localization.SetCulture(value.Culture);
        }
        Persist();
    }

    partial void OnUseMicaChanged(bool value)
    {
        _shell.UseMica = value;
        Persist();
    }

    partial void OnCheckForAppUpdatesOnStartupChanged(bool value) => Persist();
    partial void OnOutboundProxyTypeChanged(string value) => Persist();
    partial void OnOutboundProxyHostChanged(string value) => Persist();
    partial void OnOutboundProxyPortChanged(int value) => Persist();

    private void Persist()
    {
        if (_suppressPersist)
        {
            return;
        }

        // Read the latest persisted snapshot so values controlled by other pages
        // (benchmark options, profiles, apply history, custom servers) are preserved
        // verbatim instead of being clobbered with stale cached values.
        var current = _services.Settings.Load();
        _services.Settings.Save(new AppSettings
        {
            Theme = SelectedTheme,
            Language = SelectedLanguage?.Culture ?? string.Empty,
            UseMica = UseMica,
            LastNavSection = current.LastNavSection,
            TimeoutMilliseconds = current.TimeoutMilliseconds,
            ConcurrencyLimit = current.ConcurrencyLimit,
            AttemptsPerProbe = current.AttemptsPerProbe,
            AutoUpdateListOnStartup = current.AutoUpdateListOnStartup,
            CheckForAppUpdatesOnStartup = CheckForAppUpdatesOnStartup,
            OutboundProxyType = OutboundProxyType,
            OutboundProxyHost = OutboundProxyHost,
            OutboundProxyPort = OutboundProxyPort,
            CustomServers = current.CustomServers,
            SidelinedServerKeys = current.SidelinedServerKeys,
            ActiveProfileId = current.ActiveProfileId,
            Profiles = current.Profiles,
            ApplyHistory = current.ApplyHistory,
        });
    }
}
