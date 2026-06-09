using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DNSHop.App.Services;
using System;
using System.Diagnostics;
using System.Threading.Tasks;

namespace DNSHop.App.ViewModels.Pages;

internal sealed partial class AboutPageViewModel : PageViewModel
{
    private readonly AppServices _services;

    [ObservableProperty]
    private string _versionText = string.Empty;

    public AboutPageViewModel(AppServices services) : base("About", "About.Title")
    {
        _services = services;
        VersionText = string.Format(_services.Localization["About.Version"], _services.Releases.CurrentVersionText);
        _services.Localization.CultureChanged += (_, _) => VersionText = string.Format(_services.Localization["About.Version"], _services.Releases.CurrentVersionText);
    }

    public string RepositoryUrl => AppReleaseService.RepositoryUrl;
    public string IssuesUrl => AppReleaseService.IssuesUrl;
    public string DiscordUrl => AppReleaseService.DiscordUrl;
    public string KoFiUrl => AppReleaseService.KoFiUrl;
    public string TelegramUrl => AppReleaseService.TelegramUrl;
    public string DonationAddress => AppReleaseService.DonationAddress;

    [RelayCommand]
    private void OpenRepository() => OpenUrl(RepositoryUrl);

    [RelayCommand]
    private void OpenIssues() => OpenUrl(IssuesUrl);

    [RelayCommand]
    private void OpenDiscord() => OpenUrl(DiscordUrl);

    [RelayCommand]
    private void OpenKoFi() => OpenUrl(KoFiUrl);

    [RelayCommand]
    private void OpenTelegram() => OpenUrl(TelegramUrl);

    [RelayCommand]
    private async Task CopyDonationAddressAsync()
    {
        if (string.IsNullOrWhiteSpace(DonationAddress))
        {
            return;
        }

        if (Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop
            && desktop.MainWindow?.Clipboard is { } clipboard)
        {
            await clipboard.SetTextAsync(DonationAddress).ConfigureAwait(false);
        }
    }

    private static void OpenUrl(string url)
    {
        try
        {
            Process.Start(new ProcessStartInfo { FileName = url, UseShellExecute = true });
        }
        catch (Exception ex)
        {
            AppDiagnostics.WriteWarning("About", $"Open url failed: {ex.Message}");
        }
    }
}
