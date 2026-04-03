using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DNSHop.App.Collections;
using DNSHop.App.Models;
using DNSHop.App.Services;
using System;
using System.Collections.Specialized;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DNSHop.App.ViewModels;

public partial class MainWindowViewModel
{
    private CancellationTokenSource? _releaseRefreshCts;

    public BulkObservableCollection<AppReleaseInfo> ChangelogEntries { get; } = [];

    public string VersionText => $"DNS Hop v{_appReleaseService.CurrentVersionText}";

    public bool HasChangelogEntries => ChangelogEntries.Count > 0;

    public bool HasChangelogStatus => !string.IsNullOrWhiteSpace(ChangelogStatusText);

    public bool HasLatestReleaseNotesPreview => !string.IsNullOrWhiteSpace(LatestReleaseNotesPreview);

    public bool HasUpdatePromptNotes => !string.IsNullOrWhiteSpace(UpdatePromptNotes);

    public string LatestReleaseSummaryText
    {
        get
        {
            if (string.IsNullOrWhiteSpace(LatestReleaseTag))
            {
                return "Latest stable release: not checked yet.";
            }

            string typeText = string.IsNullOrWhiteSpace(LatestReleaseType)
                ? "release"
                : LatestReleaseType.ToLowerInvariant();
            string publishedText = string.IsNullOrWhiteSpace(LatestReleasePublishedText)
                ? "unknown publish date"
                : LatestReleasePublishedText;

            return $"Latest stable release: {LatestReleaseTag} ({typeText}), published {publishedText}.";
        }
    }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasChangelogStatus))]
    private string changelogStatusText = "Release history not loaded yet.";

    [ObservableProperty]
    private string updateStatusText = "Update status not checked yet.";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(LatestReleaseSummaryText))]
    private string latestReleaseTitle = "Not checked yet";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(LatestReleaseSummaryText))]
    private string latestReleaseTag = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(LatestReleaseSummaryText))]
    private string latestReleasePublishedText = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(LatestReleaseSummaryText))]
    private string latestReleaseType = string.Empty;

    [ObservableProperty]
    private string latestReleaseUrl = AppReleaseService.ReleasesUrl;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasLatestReleaseNotesPreview))]
    private string latestReleaseNotesPreview = string.Empty;

    [ObservableProperty]
    private bool isRefreshingReleaseData;

    [ObservableProperty]
    private bool isUpdateAvailable;

    [ObservableProperty]
    private bool checkForAppUpdatesOnStartup = true;

    [ObservableProperty]
    private bool isUpdatePromptVisible;

    [ObservableProperty]
    private string updatePromptTitle = string.Empty;

    [ObservableProperty]
    private string updatePromptMessage = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasUpdatePromptNotes))]
    private string updatePromptNotes = string.Empty;

    partial void OnCheckForAppUpdatesOnStartupChanged(bool value)
    {
        SaveSettingsSnapshot();

        if (!value)
        {
            UpdateStatusText = "Startup update checks are disabled. Use Check now in About to check manually.";
        }
    }

    private void InitializeAboutAndUpdates()
    {
        ChangelogEntries.CollectionChanged += OnChangelogEntriesCollectionChanged;
        OnPropertyChanged(nameof(HasChangelogEntries));

        if (CheckForAppUpdatesOnStartup)
        {
            _ = RefreshReleaseDataAsync(showPromptWhenUpdateAvailable: true, userInitiated: false);
        }
        else
        {
            UpdateStatusText = "Startup update checks are disabled. Use Check now in About to check manually.";
            ChangelogStatusText = "Release history not loaded yet.";
        }
    }

    [RelayCommand]
    private Task RefreshAboutDataAsync()
    {
        return RefreshReleaseDataAsync(showPromptWhenUpdateAvailable: true, userInitiated: true);
    }

    [RelayCommand]
    private void OpenRepository()
    {
        OpenExternalUrl(AppReleaseService.RepositoryUrl, "GitHub repository");
    }

    [RelayCommand]
    private void OpenDiscord()
    {
        OpenExternalUrl(AppReleaseService.DiscordUrl, "Discord server");
    }

    [RelayCommand]
    private void OpenKoFi()
    {
        OpenExternalUrl(AppReleaseService.KoFiUrl, "Ko-Fi page");
    }

    [RelayCommand]
    private void OpenReleaseLink(string? releaseUrl)
    {
        OpenExternalUrl(
            string.IsNullOrWhiteSpace(releaseUrl) ? LatestReleaseUrl : releaseUrl,
            "release page");
    }

    [RelayCommand]
    private void AcceptUpdatePrompt()
    {
        OpenExternalUrl(LatestReleaseUrl, "release page");
        IsUpdatePromptVisible = false;
    }

    [RelayCommand]
    private void DismissUpdatePrompt()
    {
        IsUpdatePromptVisible = false;
    }

    [RelayCommand]
    private void DisableStartupUpdatePrompt()
    {
        CheckForAppUpdatesOnStartup = false;
        IsUpdatePromptVisible = false;
        StatusMessage = "Startup update prompts disabled. You can still check manually in About.";
    }

    private async Task RefreshReleaseDataAsync(bool showPromptWhenUpdateAvailable, bool userInitiated)
    {
        if (IsRefreshingReleaseData)
        {
            return;
        }

        _releaseRefreshCts?.Cancel();
        _releaseRefreshCts?.Dispose();
        _releaseRefreshCts = new CancellationTokenSource(TimeSpan.FromSeconds(20));

        CancellationToken cancellationToken = _releaseRefreshCts.Token;
        IsRefreshingReleaseData = true;
        UpdateStatusText = "Checking for DNS Hop updates...";
        ChangelogStatusText = "Loading release history from GitHub...";

        try
        {
            AppReleaseSnapshot snapshot = await _appReleaseService
                .GetReleaseSnapshotAsync(cancellationToken)
                .ConfigureAwait(true);

            ChangelogEntries.ReplaceRange(snapshot.Releases);
            OnPropertyChanged(nameof(HasChangelogEntries));

            ChangelogStatusText = snapshot.Releases.Length == 0
                ? "No public release entries were found."
                : $"Loaded {snapshot.Releases.Length} release entries.";

            if (snapshot.LatestStableRelease is null)
            {
                LatestReleaseTitle = "Not available";
                LatestReleaseTag = string.Empty;
                LatestReleasePublishedText = string.Empty;
                LatestReleaseType = string.Empty;
                LatestReleaseUrl = AppReleaseService.ReleasesUrl;
                LatestReleaseNotesPreview = string.Empty;
                IsUpdateAvailable = false;
                UpdateStatusText = "Unable to determine the latest stable release.";
                return;
            }

            AppReleaseInfo latestRelease = snapshot.LatestStableRelease;
            LatestReleaseTitle = latestRelease.DisplayTitle;
            LatestReleaseTag = latestRelease.Tag;
            LatestReleasePublishedText = latestRelease.PublishedText;
            LatestReleaseType = latestRelease.ReleaseType;
            LatestReleaseUrl = string.IsNullOrWhiteSpace(latestRelease.HtmlUrl)
                ? AppReleaseService.ReleasesUrl
                : latestRelease.HtmlUrl;
            LatestReleaseNotesPreview = BuildNotesPreview(latestRelease.Notes);

            bool hasComparableVersion = latestRelease.ParsedVersion is not null;
            IsUpdateAvailable = hasComparableVersion && latestRelease.ParsedVersion! > _appReleaseService.CurrentVersion;

            UpdateStatusText = IsUpdateAvailable
                ? $"Update available: {latestRelease.Tag}. You are on v{_appReleaseService.CurrentVersionText}."
                : $"You are up to date on v{_appReleaseService.CurrentVersionText}.";

            if (IsUpdateAvailable && showPromptWhenUpdateAvailable)
            {
                ShowUpdatePrompt(latestRelease);
            }
            else if (userInitiated)
            {
                StatusMessage = UpdateStatusText;
            }
        }
        catch (OperationCanceledException)
        {
            if (userInitiated)
            {
                UpdateStatusText = "Update check canceled.";
                ChangelogStatusText = "Release history refresh canceled.";
                StatusMessage = UpdateStatusText;
            }
        }
        catch (Exception ex)
        {
            IsUpdateAvailable = false;
            UpdateStatusText = $"Update check failed: {ex.Message}";
            ChangelogStatusText = $"Release history could not be loaded: {ex.Message}";

            if (userInitiated)
            {
                StatusMessage = UpdateStatusText;
            }
        }
        finally
        {
            IsRefreshingReleaseData = false;
            _releaseRefreshCts?.Dispose();
            _releaseRefreshCts = null;
        }
    }

    private void ShowUpdatePrompt(AppReleaseInfo latestRelease)
    {
        UpdatePromptTitle = $"Update available: {latestRelease.Tag}";
        UpdatePromptMessage =
            $"You are on v{_appReleaseService.CurrentVersionText}. DNS Hop {latestRelease.Tag} was published {latestRelease.PublishedText}. Open the release page now?";
        UpdatePromptNotes = BuildNotesPreview(latestRelease.Notes);
        IsUpdatePromptVisible = true;
        StatusMessage = $"Update available: {latestRelease.Tag}.";
    }

    private void OpenExternalUrl(string? url, string targetDescription)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            StatusMessage = $"No {targetDescription} URL is available.";
            return;
        }

        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = url,
                UseShellExecute = true,
            });

            StatusMessage = $"Opened {targetDescription}.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Could not open {targetDescription}: {ex.Message}";
        }
    }

    private static string BuildNotesPreview(string? notes)
    {
        if (string.IsNullOrWhiteSpace(notes))
        {
            return string.Empty;
        }

        string preview = string.Join(
            "\n",
            notes
                .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Where(static line => !string.IsNullOrWhiteSpace(line))
                .Take(4));

        if (preview.Length <= 360)
        {
            return preview;
        }

        return $"{preview[..357]}...";
    }

    private void OnChangelogEntriesCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        OnPropertyChanged(nameof(HasChangelogEntries));
    }
}
