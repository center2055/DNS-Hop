using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using Avalonia.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DNSHop.App.Collections;
using DNSHop.App.Models;
using DNSHop.App.Services;
using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DNSHop.App.ViewModels;

public partial class MainWindowViewModel : ViewModelBase
{
    private readonly IDnsBenchmarkService _dnsBenchmarkService;
    private readonly DnsServerListService _dnsServerListService;
    private readonly RecommendationService _recommendationService;
    private readonly ExportService _exportService;
    private readonly AppSettingsService _appSettingsService;

    private CancellationTokenSource? _benchmarkCts;
    private CancellationTokenSource? _remoteRefreshCts;
    private CancellationTokenSource? _filterDebounceCts;
    private DispatcherTimer? _elapsedTimer;
    private readonly Stopwatch _uiElapsedStopwatch = new();
    private SortMode _sortMode = SortMode.BestPerformance;
    private bool _suppressSettingsSave;
    private bool _isRemoteRefreshRunning;
    private const int FilterDebounceMs = 180;

    internal MainWindowViewModel(
        IDnsBenchmarkService dnsBenchmarkService,
        DnsServerListService dnsServerListService,
        RecommendationService recommendationService,
        ExportService exportService,
        AppSettingsService appSettingsService)
    {
        _dnsBenchmarkService = dnsBenchmarkService;
        _dnsServerListService = dnsServerListService;
        _recommendationService = recommendationService;
        _exportService = exportService;
        _appSettingsService = appSettingsService;

        IntroductionText =
            "DNS Hop benchmarks DNS resolver performance across classic UDP/TCP DNS, " +
            "DNS over HTTPS (DoH), and DNS over TLS (DoT).\n\n" +
            "The benchmark uses three latency probes:\n" +
            "- Cached: google.com\n" +
            "- Uncached: randomized GUID.com\n" +
            "- DotCom: com NS query\n\n" +
            "Reliability checks identify dead servers, NXDOMAIN redirectors, and DNSSEC validating resolvers.";

        ConclusionText = "Run a benchmark to generate recommendations for primary and secondary DNS.";

        LoadPersistedSettings();
        SwitchTheme(SelectedTheme);
        SaveSettingsSnapshot();

        // Theme can be read from persisted settings before the window resource dictionary
        // is fully attached; re-apply on UI loaded cycle to avoid dark/light mismatches.
        Dispatcher.UIThread.Post(
            () => SwitchTheme(SelectedTheme),
            DispatcherPriority.Loaded);

        // Startup flow: load list immediately so the UI is ready for one-click benchmarking.
        _ = LoadServersAsync();
    }

    public BulkObservableCollection<DnsServerResultViewModel> Servers { get; } = [];

    public BulkObservableCollection<DnsServerResultViewModel> DisplayedServers { get; } = [];

    [ObservableProperty]
    private DnsServerResultViewModel? selectedServer;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(StartBenchmarkCommand))]
    [NotifyCanExecuteChangedFor(nameof(CancelBenchmarkCommand))]
    private bool isBenchmarkRunning;

    [ObservableProperty]
    private bool isServerListLoading;

    [ObservableProperty]
    private string statusMessage = "Ready.";

    [ObservableProperty]
    private string introductionText = string.Empty;

    [ObservableProperty]
    private string conclusionText = string.Empty;

    [ObservableProperty]
    private int queriesRemaining;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(PercentCompletedText))]
    private double percentCompleted;

    [ObservableProperty]
    private string elapsed = "00:00:00";

    [ObservableProperty]
    private int timeoutMilliseconds = 2500;

    [ObservableProperty]
    private int concurrencyLimit = 8;

    [ObservableProperty]
    private int attemptsPerProbe = 1;

    [ObservableProperty]
    private bool autoUpdateListOnStartup = true;

    public string[] AvailableProxyTypes { get; } = ["None", "Https", "Socks4", "Socks5"];

    [ObservableProperty]
    private string selectedProxyType = "None";

    [ObservableProperty]
    private string proxyHost = string.Empty;

    [ObservableProperty]
    private int proxyPort = 1080;

    [ObservableProperty]
    private string filterText = string.Empty;

    [ObservableProperty]
    private double chartScaleMaximum = 300;

    [ObservableProperty]
    private double cachedScaleMaximum = 120;

    [ObservableProperty]
    private double uncachedScaleMaximum = 250;

    [ObservableProperty]
    private double dotComScaleMaximum = 120;

    public string[] AvailableThemes { get; } = ["Dark", "Light"];

    [ObservableProperty]
    private string selectedTheme = "Dark";

    partial void OnSelectedThemeChanged(string value)
    {
        SwitchTheme(value);
        SaveSettingsSnapshot();
    }

    public string PercentCompletedText => $"{PercentCompleted:0.0}%";

    private bool CanStartBenchmark => !IsBenchmarkRunning && Servers.Count > 0;

    private bool CanCancelBenchmark => IsBenchmarkRunning;

    partial void OnFilterTextChanged(string value)
    {
        DebounceFilterAndSort();
    }

    partial void OnAttemptsPerProbeChanged(int value)
    {
        UpdateIdleProgressSnapshot();
        SaveSettingsSnapshot();
    }

    partial void OnTimeoutMillisecondsChanged(int value)
    {
        SaveSettingsSnapshot();
    }

    partial void OnConcurrencyLimitChanged(int value)
    {
        SaveSettingsSnapshot();
    }

    partial void OnAutoUpdateListOnStartupChanged(bool value)
    {
        SaveSettingsSnapshot();
    }

    partial void OnSelectedProxyTypeChanged(string value)
    {
        SaveSettingsSnapshot();
    }

    partial void OnProxyHostChanged(string value)
    {
        SaveSettingsSnapshot();
    }

    partial void OnProxyPortChanged(int value)
    {
        SaveSettingsSnapshot();
    }

    private void SwitchTheme(string themeMode)
    {
        bool light = string.Equals(themeMode, "Light", StringComparison.OrdinalIgnoreCase);
        var targetTheme = light ? Avalonia.Styling.ThemeVariant.Light : Avalonia.Styling.ThemeVariant.Dark;

        if (Application.Current is null)
        {
            return;
        }

        Application.Current.RequestedThemeVariant = targetTheme;

        try
        {
            SukiUI.SukiTheme.GetInstance().ChangeBaseTheme(targetTheme);
        }
        catch
        {
            // Suki theme switching is best-effort; palette updates below keep UI usable.
        }

        ApplyPalette(light);
    }

    [RelayCommand]
    private async Task LoadServersAsync()
    {
        if (IsBenchmarkRunning || IsServerListLoading)
        {
            return;
        }

        _remoteRefreshCts?.Cancel();
        _remoteRefreshCts?.Dispose();
        _remoteRefreshCts = null;

        IsServerListLoading = true;

        try
        {
            StatusMessage = "Loading DNS server list...";
            var servers = await _dnsServerListService
                .GetLocalServersAsync(CancellationToken.None)
                .ConfigureAwait(true);

            var localRows = servers
                .Select(static server => new DnsServerResultViewModel(server))
                .ToArray();

            Servers.ReplaceRange(localRows);

            ApplyFilterAndSort();
            UpdateIdleProgressSnapshot();

            StatusMessage = $"Loaded {Servers.Count} DNS endpoints.";
            StartBenchmarkCommand.NotifyCanExecuteChanged();
        }
        catch (Exception ex)
        {
            StatusMessage = $"Failed to load server list: {ex.Message}";
        }
        finally
        {
            IsServerListLoading = false;
        }

        if (AutoUpdateListOnStartup)
        {
            _ = RefreshRemoteServersAsync();
        }
    }

    [RelayCommand(CanExecute = nameof(CanStartBenchmark))]
    private async Task StartBenchmarkAsync()
    {
        _benchmarkCts?.Cancel();
        _benchmarkCts?.Dispose();
        _benchmarkCts = new CancellationTokenSource();

        IsBenchmarkRunning = true;
        PercentCompleted = 0;
        QueriesRemaining = 0;
        Elapsed = "00:00:00";
        StartElapsedTicker();

        try
        {
            var activeServers = Servers
                .Where(static row => !row.IsSidelined)
                .Select(static row => row.Server)
                .ToArray();

            if (activeServers.Length == 0)
            {
                StatusMessage = "No active servers left. Un-sideline at least one endpoint.";
                return;
            }

            StatusMessage = $"Benchmarking {activeServers.Length} servers...";

            if (!TryBuildProxyType(SelectedProxyType, out var outboundProxyType))
            {
                StatusMessage = $"Unknown proxy type '{SelectedProxyType}'.";
                return;
            }

            if (outboundProxyType != DnsOutboundProxyType.None
                && string.IsNullOrWhiteSpace(ProxyHost))
            {
                StatusMessage = "Proxy host is required when outbound proxy is enabled.";
                return;
            }

            var options = new DnsBenchmarkOptions
            {
                TimeoutMilliseconds = TimeoutMilliseconds,
                ConcurrencyLimit = ConcurrencyLimit,
                AttemptsPerProbe = AttemptsPerProbe,
                OutboundProxyType = outboundProxyType,
                OutboundProxyHost = ProxyHost,
                OutboundProxyPort = ProxyPort,
            };

            var progress = new Progress<DnsBenchmarkProgress>(OnBenchmarkProgress);

            var benchmarkResults = await _dnsBenchmarkService
                .BenchmarkAsync(activeServers, options, progress, _benchmarkCts.Token)
                .ConfigureAwait(true);

            var resultMap = benchmarkResults
                .ToDictionary(
                    result => $"{result.Server.Protocol}|{result.Server.EndpointDisplay}",
                    StringComparer.OrdinalIgnoreCase);

            foreach (var row in Servers)
            {
                if (resultMap.TryGetValue($"{row.Server.Protocol}|{row.Server.EndpointDisplay}", out var result))
                {
                    row.ApplyBenchmarkResult(result);
                }
            }

            ApplyFilterAndSort();

            ConclusionText = _recommendationService.BuildConclusion(
                Servers.Select(static row => row.ToResultModel()).ToArray());

            StatusMessage = $"Benchmark complete. Tested {benchmarkResults.Count} active endpoints.";
            PercentCompleted = 100;
            QueriesRemaining = 0;
        }
        catch (OperationCanceledException)
        {
            StatusMessage = "Benchmark canceled.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Benchmark failed: {ex.Message}";
        }
        finally
        {
            StopElapsedTicker();
            Elapsed = _uiElapsedStopwatch.Elapsed.ToString(@"hh\:mm\:ss");
            IsBenchmarkRunning = false;
            _benchmarkCts?.Dispose();
            _benchmarkCts = null;

            StartBenchmarkCommand.NotifyCanExecuteChanged();
            CancelBenchmarkCommand.NotifyCanExecuteChanged();
        }
    }

    [RelayCommand(CanExecute = nameof(CanCancelBenchmark))]
    private void CancelBenchmark()
    {
        _benchmarkCts?.Cancel();
    }

    [RelayCommand]
    private async Task ExportCsvAsync()
    {
        try
        {
            string? destinationPath = await PickExportPathAsync("Export DNS Hop Results (CSV)", "csv", "CSV file")
                .ConfigureAwait(true);

            if (string.IsNullOrWhiteSpace(destinationPath))
            {
                StatusMessage = "CSV export canceled.";
                return;
            }

            string path = await _exportService
                .ExportCsvAsync(
                    Servers.Select(static row => row.ToResultModel()).ToArray(),
                    destinationPath,
                    CancellationToken.None)
                .ConfigureAwait(true);

            StatusMessage = $"CSV exported to: {path}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"CSV export failed ({ex.GetType().Name}): {ex.Message}";
        }
    }

    [RelayCommand]
    private async Task ExportJsonAsync()
    {
        try
        {
            string? destinationPath = await PickExportPathAsync("Export DNS Hop Results (JSON)", "json", "JSON file")
                .ConfigureAwait(true);

            if (string.IsNullOrWhiteSpace(destinationPath))
            {
                StatusMessage = "JSON export canceled.";
                return;
            }

            string path = await _exportService
                .ExportJsonAsync(
                    Servers.Select(static row => row.ToResultModel()).ToArray(),
                    destinationPath,
                    CancellationToken.None)
                .ConfigureAwait(true);

            StatusMessage = $"JSON exported to: {path}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"JSON export failed ({ex.GetType().Name}): {ex.Message}";
        }
    }

    [RelayCommand]
    private async Task CopyChartPngToClipboardAsync()
    {
        try
        {
            bool copied = await _exportService
                .CopyChartToClipboardAsync(
                    Servers.Select(static row => row.ToResultModel()).ToArray(),
                    CancellationToken.None)
                .ConfigureAwait(true);

            StatusMessage = copied
                ? "Chart copied to clipboard."
                : "Clipboard not available on this system.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Clipboard copy failed ({ex.GetType().Name}): {ex.Message}";
        }
    }

    [RelayCommand]
    private void RemoveSelected(DnsServerResultViewModel? targetServer)
    {
        var target = targetServer ?? SelectedServer;

        if (target is null)
        {
            StatusMessage = "No nameserver selected to copy.";
            return;
        }

        Servers.Remove(target);

        if (ReferenceEquals(SelectedServer, target))
        {
            SelectedServer = null;
        }

        ApplyFilterAndSort();
        UpdateIdleProgressSnapshot();
        StartBenchmarkCommand.NotifyCanExecuteChanged();
    }

    [RelayCommand]
    private void SidelineSelected(DnsServerResultViewModel? targetServer)
    {
        var target = targetServer ?? SelectedServer;

        if (target is null)
        {
            return;
        }

        target.IsSidelined = !target.IsSidelined;
        ApplyFilterAndSort();
        UpdateIdleProgressSnapshot();
    }

    [RelayCommand]
    private void PinSelected(DnsServerResultViewModel? targetServer)
    {
        var target = targetServer ?? SelectedServer;

        if (target is null)
        {
            return;
        }

        target.IsPinned = !target.IsPinned;
        ApplyFilterAndSort();
        UpdateIdleProgressSnapshot();
    }

    [RelayCommand]
    private void RemoveDead()
    {
        RemoveWhere(static row => row.Status == DnsServerStatus.Dead);
    }

    [RelayCommand]
    private void RemoveNonDnssec()
    {
        RemoveWhere(static row => !row.SupportsDnssec);
    }

    [RelayCommand]
    private void RemoveRedirecting()
    {
        RemoveWhere(static row => row.RedirectsNxDomain);
    }

    [RelayCommand]
    private void SortByBestPerformance()
    {
        _sortMode = SortMode.BestPerformance;
        ApplyFilterAndSort();
    }

    [RelayCommand]
    private void SortByCached()
    {
        _sortMode = SortMode.Cached;
        ApplyFilterAndSort();
    }

    [RelayCommand]
    private void SortByUncached()
    {
        _sortMode = SortMode.Uncached;
        ApplyFilterAndSort();
    }

    [RelayCommand]
    private async Task CopyIpAddressAsync(DnsServerResultViewModel? targetServer)
    {
        var target = targetServer ?? SelectedServer;

        if (target is null)
        {
            return;
        }

        if (Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop
            && desktop.MainWindow?.Clipboard is { } clipboard)
        {
            await clipboard.SetTextAsync(target.Server.AddressOrHost);
            StatusMessage = $"Copied: {target.Server.AddressOrHost}";
        }
    }

    private void OnBenchmarkProgress(DnsBenchmarkProgress progress)
    {
        QueriesRemaining = progress.QueriesRemaining;
        PercentCompleted = progress.PercentCompleted;
        Elapsed = progress.Elapsed.ToString(@"hh\:mm\:ss");

        StatusMessage = $"Testing {progress.CurrentServer} ({progress.CompletedQueries}/{progress.TotalQueries})";
    }

    private void StartElapsedTicker()
    {
        StopElapsedTicker();
        _uiElapsedStopwatch.Restart();

        _elapsedTimer = new DispatcherTimer(
            TimeSpan.FromMilliseconds(200),
            DispatcherPriority.Background,
            OnElapsedTimerTick);
    }

    private void StopElapsedTicker()
    {
        if (_elapsedTimer is not null)
        {
            _elapsedTimer.Tick -= OnElapsedTimerTick;
            _elapsedTimer.Stop();
            _elapsedTimer = null;
        }

        if (_uiElapsedStopwatch.IsRunning)
        {
            _uiElapsedStopwatch.Stop();
        }
    }

    private void OnElapsedTimerTick(object? sender, EventArgs e)
    {
        if (!IsBenchmarkRunning)
        {
            return;
        }

        Elapsed = _uiElapsedStopwatch.Elapsed.ToString(@"hh\:mm\:ss");
    }

    private void RemoveWhere(Func<DnsServerResultViewModel, bool> predicate)
    {
        var toRemove = Servers.Where(predicate).ToArray();

        foreach (var item in toRemove)
        {
            Servers.Remove(item);
        }

        ApplyFilterAndSort();
        StartBenchmarkCommand.NotifyCanExecuteChanged();
        UpdateIdleProgressSnapshot();
    }

    private void ApplyFilterAndSort()
    {
        IEnumerable<DnsServerResultViewModel> filtered = Servers;

        if (!string.IsNullOrWhiteSpace(FilterText))
        {
            string normalizedTerm = FilterText.Trim().ToLowerInvariant();
            filtered = filtered.Where(row => row.MatchesFilter(normalizedTerm));
        }

        var pinned = OrderByCurrentSort(filtered.Where(static row => row.IsPinned));
        var unpinned = OrderByCurrentSort(filtered.Where(static row => !row.IsPinned));

        var orderedRows = pinned.Concat(unpinned).ToArray();
        DisplayedServers.ReplaceRange(orderedRows);

        ChartScaleMaximum = CalculateChartScaleMaximum();
        CachedScaleMaximum = CalculateProbeScaleMaximum(DisplayedServers, static row => row.CachedMilliseconds, fallback: 120);
        UncachedScaleMaximum = CalculateProbeScaleMaximum(DisplayedServers, static row => row.UncachedMilliseconds, fallback: 250);
        DotComScaleMaximum = CalculateProbeScaleMaximum(DisplayedServers, static row => row.DotComMilliseconds, fallback: 120);

        ApplyPerProtocolScaleAssignments();
    }

    private void DebounceFilterAndSort()
    {
        _filterDebounceCts?.Cancel();
        _filterDebounceCts?.Dispose();
        _filterDebounceCts = new CancellationTokenSource();
        CancellationToken token = _filterDebounceCts.Token;

        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(FilterDebounceMs, token).ConfigureAwait(false);
                if (token.IsCancellationRequested)
                {
                    return;
                }

                Dispatcher.UIThread.Post(
                    () =>
                    {
                        if (!token.IsCancellationRequested)
                        {
                            ApplyFilterAndSort();
                        }
                    },
                    DispatcherPriority.Background);
            }
            catch (OperationCanceledException)
            {
                // Newer filter input superseded this pending refresh.
            }
        }, token);
    }

    private async Task RefreshRemoteServersAsync()
    {
        if (IsBenchmarkRunning || _isRemoteRefreshRunning)
        {
            return;
        }

        _isRemoteRefreshRunning = true;
        _remoteRefreshCts?.Cancel();
        _remoteRefreshCts?.Dispose();
        _remoteRefreshCts = new CancellationTokenSource(TimeSpan.FromSeconds(4));

        try
        {
            StatusMessage = $"Loaded {Servers.Count} DNS endpoints. Updating public feed...";

            var remoteServers = await _dnsServerListService
                .GetRemoteServersAsync(_remoteRefreshCts.Token)
                .ConfigureAwait(true);

            int added = MergeRemoteServers(remoteServers);

            if (added > 0)
            {
                ApplyFilterAndSort();
                UpdateIdleProgressSnapshot();
            }

            StatusMessage = added > 0
                ? $"Loaded {Servers.Count} DNS endpoints. Added {added} from public feed."
                : $"Loaded {Servers.Count} DNS endpoints. Public feed already covered.";
        }
        catch (OperationCanceledException)
        {
            StatusMessage = $"Loaded {Servers.Count} DNS endpoints.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Loaded {Servers.Count} DNS endpoints. Public feed update failed: {ex.Message}";
        }
        finally
        {
            _isRemoteRefreshRunning = false;
            _remoteRefreshCts?.Dispose();
            _remoteRefreshCts = null;
        }
    }

    private int MergeRemoteServers(IEnumerable<DnsServerDefinition> remoteServers)
    {
        var existingKeys = new HashSet<string>(
            Servers.Select(static row => $"{row.Server.Protocol}|{row.Server.EndpointDisplay}"),
            StringComparer.OrdinalIgnoreCase);

        var pendingAdds = new List<DnsServerResultViewModel>();

        foreach (var server in remoteServers)
        {
            string key = $"{server.Protocol}|{server.EndpointDisplay}";
            if (!existingKeys.Add(key))
            {
                continue;
            }

            pendingAdds.Add(new DnsServerResultViewModel(server));
        }

        if (pendingAdds.Count > 0)
        {
            Servers.AddRange(pendingAdds);
        }

        return pendingAdds.Count;
    }

    private void UpdateIdleProgressSnapshot()
    {
        if (IsBenchmarkRunning)
        {
            return;
        }

        // When not running, show an idle dashboard snapshot rather than projected query count.
        QueriesRemaining = 0;
        PercentCompleted = 0;
        Elapsed = "00:00:00";
    }

    private static void ApplyPalette(bool light)
    {
        if (Application.Current is null)
        {
            return;
        }

        if (light)
        {
            SetBrush("PageBackgroundBrush", "#FFF3F6FB");
            SetBrush("ShellCardBrush", "#FFFFFFFF");
            SetBrush("ControlsCardBrush", "#FFFFFFFF");
            SetBrush("ContentPanelBrush", "#FFEAF0F9");
            SetBrush("CardBrush", "#FFF9FBFF");
            SetBrush("CardBorderBrush", "#FFB8C7DD");
            SetBrush("PrimaryTextBrush", "#FF11263C");
            SetBrush("MutedTextBrush", "#FF3C5574");
            SetBrush("ButtonBackgroundBrush", "#FFF7FAFF");
            SetBrush("ButtonBorderBrush", "#FF9EB2CF");
            SetBrush("ButtonHoverBackgroundBrush", "#FFEAF2FF");
            SetBrush("ButtonHoverBorderBrush", "#FF7F98BE");
            SetBrush("ButtonPressedBackgroundBrush", "#FFE0ECFF");
            SetBrush("ButtonPressedBorderBrush", "#FF5D84BC");
            SetBrush("ButtonDisabledBackgroundBrush", "#FFF2F5FA");
            SetBrush("ButtonDisabledBorderBrush", "#FFD1DAE8");
            SetBrush("ButtonDisabledForegroundBrush", "#FF8EA1BF");
            SetBrush("ButtonAccentBackgroundBrush", "#FF3B8CF8");
            SetBrush("ButtonAccentBorderBrush", "#FF3B8CF8");
            SetBrush("ButtonAccentHoverBackgroundBrush", "#FF2E7BE9");
            SetBrush("ButtonAccentHoverBorderBrush", "#FF2E7BE9");
            SetBrush("ButtonAccentPressedBackgroundBrush", "#FF266CD0");
            SetBrush("ButtonAccentPressedBorderBrush", "#FF266CD0");
            SetBrush("ButtonAccentForegroundBrush", "#FFFFFFFF");
            SetBrush("InputBackgroundBrush", "#FFFFFFFF");
            SetBrush("InputBorderBrush", "#FF9FB5D4");
            SetBrush("InputForegroundBrush", "#FF10253B");
            SetBrush("ProgressTrackBrush", "#FFDDE6F5");
            SetBrush("ProgressFillBrush", "#FF3C90FF");
            SetBrush("ResponseBarBackgroundBrush", "#FFDCE6F5");
            SetBrush("ResponseBarTextBrush", "#FF15304F");
            SetBrush("ResponseBarNoDataBackgroundBrush", "#FFE5EDF9");
            SetBrush("ResponseBarNoDataTextBrush", "#FF5B7191");
            SetBrush("ResponseBarBorderBrush", "#FFB2C3DC");
            SetBrush("DataGridSelectedRowBackgroundBrush", "#FFD7E6FA");
            SetBrush("DataGridSelectedRowBorderBrush", "#FF7FA4D9");

            SetBrush("CheckBoxBoxBorderBrush", "#FFA3ABB8");
            SetBrush("CheckBoxBoxBorderHoverBrush", "#FF8892A1");
            SetBrush("CheckBoxBoxBackgroundBrush", "#FFF4F6F9");
            SetBrush("CheckBoxCheckFillBrush", "#FF1E66D8");
            SetBrush("CheckBoxCheckGlyphBrush", "#FFFFFFFF");
        }
        else
        {
            SetBrush("PageBackgroundBrush", "#FF162339");
            SetBrush("ShellCardBrush", "#FF223350");
            SetBrush("ControlsCardBrush", "#FF1F304B");
            SetBrush("ContentPanelBrush", "#FF1D2E49");
            SetBrush("CardBrush", "#FF253A5A");
            SetBrush("CardBorderBrush", "#FF50668A");
            SetBrush("PrimaryTextBrush", "#FFEAF2FF");
            SetBrush("MutedTextBrush", "#FFD9E7FF");
            SetBrush("ButtonBackgroundBrush", "#FF2A3B5C");
            SetBrush("ButtonBorderBrush", "#FF50668A");
            SetBrush("ButtonHoverBackgroundBrush", "#FF324A74");
            SetBrush("ButtonHoverBorderBrush", "#FF6D88B5");
            SetBrush("ButtonPressedBackgroundBrush", "#FF223554");
            SetBrush("ButtonPressedBorderBrush", "#FF7D9ECC");
            SetBrush("ButtonDisabledBackgroundBrush", "#FF253651");
            SetBrush("ButtonDisabledBorderBrush", "#FF3E577A");
            SetBrush("ButtonDisabledForegroundBrush", "#FFAFC3E0");
            SetBrush("ButtonAccentBackgroundBrush", "#FF3C90FF");
            SetBrush("ButtonAccentBorderBrush", "#FF3C90FF");
            SetBrush("ButtonAccentHoverBackgroundBrush", "#FF5CA6FF");
            SetBrush("ButtonAccentHoverBorderBrush", "#FF5CA6FF");
            SetBrush("ButtonAccentPressedBackgroundBrush", "#FF327AE0");
            SetBrush("ButtonAccentPressedBorderBrush", "#FF327AE0");
            SetBrush("ButtonAccentForegroundBrush", "#FFFFFFFF");
            SetBrush("InputBackgroundBrush", "#FF2B3D5F");
            SetBrush("InputBorderBrush", "#FF4E658B");
            SetBrush("InputForegroundBrush", "#FFEAF2FF");
            SetBrush("ProgressTrackBrush", "#FF1A2942");
            SetBrush("ProgressFillBrush", "#FF3C90FF");
            SetBrush("ResponseBarBackgroundBrush", "#FF1A2538");
            SetBrush("ResponseBarTextBrush", "#FFFFFFFF");
            SetBrush("ResponseBarNoDataBackgroundBrush", "#FF24395A");
            SetBrush("ResponseBarNoDataTextBrush", "#FFBFD0EA");
            SetBrush("ResponseBarBorderBrush", "#FF3F587D");
            SetBrush("DataGridSelectedRowBackgroundBrush", "#FF2F4E76");
            SetBrush("DataGridSelectedRowBorderBrush", "#FF6B8FBC");

            SetBrush("CheckBoxBoxBorderBrush", "#FF8A95A8");
            SetBrush("CheckBoxBoxBorderHoverBrush", "#FFA1AABC");
            SetBrush("CheckBoxBoxBackgroundBrush", "#FF303744");
            SetBrush("CheckBoxCheckFillBrush", "#FF3C90FF");
            SetBrush("CheckBoxCheckGlyphBrush", "#FFFFFFFF");
        }
    }

    private static void SetBrush(string key, string colorHex)
    {
        if (Application.Current is null)
        {
            return;
        }

        var brush = new SolidColorBrush(Color.Parse(colorHex));
        Application.Current.Resources[key] = brush;

        if (Application.Current.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop
            && desktop.MainWindow is not null)
        {
            desktop.MainWindow.Resources[key] = brush;
        }
    }

    private void LoadPersistedSettings()
    {
        _suppressSettingsSave = true;

        try
        {
            AppSettings settings = _appSettingsService.Load();

            SelectedTheme = settings.Theme;
            TimeoutMilliseconds = settings.TimeoutMilliseconds;
            ConcurrencyLimit = settings.ConcurrencyLimit;
            AttemptsPerProbe = settings.AttemptsPerProbe;
            AutoUpdateListOnStartup = settings.AutoUpdateListOnStartup;
            SelectedProxyType = settings.OutboundProxyType;
            ProxyHost = settings.OutboundProxyHost;
            ProxyPort = settings.OutboundProxyPort;
        }
        finally
        {
            _suppressSettingsSave = false;
        }
    }

    private void SaveSettingsSnapshot()
    {
        if (_suppressSettingsSave)
        {
            return;
        }

        _appSettingsService.Save(new AppSettings
        {
            Theme = SelectedTheme,
            TimeoutMilliseconds = TimeoutMilliseconds,
            ConcurrencyLimit = ConcurrencyLimit,
            AttemptsPerProbe = AttemptsPerProbe,
            AutoUpdateListOnStartup = AutoUpdateListOnStartup,
            OutboundProxyType = SelectedProxyType,
            OutboundProxyHost = ProxyHost,
            OutboundProxyPort = ProxyPort,
        });
    }

    public void PersistSettings()
    {
        SaveSettingsSnapshot();
    }

    public void ReapplyTheme()
    {
        SwitchTheme(SelectedTheme);
    }

    private IOrderedEnumerable<DnsServerResultViewModel> OrderByCurrentSort(IEnumerable<DnsServerResultViewModel> rows)
    {
        return _sortMode switch
        {
            SortMode.Cached => rows
                .OrderBy(static row => row.CachedMilliseconds ?? double.MaxValue)
                .ThenBy(static row => row.Endpoint, StringComparer.OrdinalIgnoreCase),

            SortMode.Uncached => rows
                .OrderBy(static row => row.UncachedMilliseconds ?? double.MaxValue)
                .ThenBy(static row => row.Endpoint, StringComparer.OrdinalIgnoreCase),

            _ => rows
                .OrderBy(static row => row.AverageMilliseconds ?? double.MaxValue)
                .ThenBy(static row => row.Endpoint, StringComparer.OrdinalIgnoreCase),
        };
    }

    private double CalculateChartScaleMaximum()
    {
        var observed = DisplayedServers
            .SelectMany(static row => new[]
            {
                row.CachedMilliseconds ?? 0,
                row.UncachedMilliseconds ?? 0,
                row.DotComMilliseconds ?? 0,
            })
            .Where(static value => value > 0)
            .OrderBy(static value => value)
            .ToArray();

        if (observed.Length == 0)
        {
            return 150;
        }

        // Use P95 to keep bars readable when a few servers are extreme outliers.
        int p95Index = (int)Math.Ceiling(observed.Length * 0.95) - 1;
        p95Index = Math.Clamp(p95Index, 0, observed.Length - 1);
        double scaleAnchor = observed[p95Index];

        return Math.Max(50, Math.Ceiling(scaleAnchor / 10) * 10);
    }

    private static double CalculateProbeScaleMaximum(
        IEnumerable<DnsServerResultViewModel> rows,
        Func<DnsServerResultViewModel, double?> selector,
        double fallback)
    {
        var observed = rows
            .Select(selector)
            .Where(static value => value is > 0)
            .Select(static value => value!.Value)
            .OrderBy(static value => value)
            .ToArray();

        if (observed.Length == 0)
        {
            return fallback;
        }

        int p95Index = (int)Math.Ceiling(observed.Length * 0.95) - 1;
        p95Index = Math.Clamp(p95Index, 0, observed.Length - 1);
        double scaleAnchor = observed[p95Index];

        return Math.Max(20, Math.Ceiling(scaleAnchor / 10) * 10);
    }

    private void ApplyPerProtocolScaleAssignments()
    {
        var groupedByProtocol = DisplayedServers
            .GroupBy(static row => row.Protocol, StringComparer.OrdinalIgnoreCase);

        foreach (var protocolGroup in groupedByProtocol)
        {
            double cachedScale = CalculateProbeScaleMaximum(protocolGroup, static row => row.CachedMilliseconds, fallback: 120);
            double uncachedScale = CalculateProbeScaleMaximum(protocolGroup, static row => row.UncachedMilliseconds, fallback: 250);
            double dotComScale = CalculateProbeScaleMaximum(protocolGroup, static row => row.DotComMilliseconds, fallback: 120);

            foreach (var row in protocolGroup)
            {
                row.CachedScaleMaximum = cachedScale;
                row.UncachedScaleMaximum = uncachedScale;
                row.DotComScaleMaximum = dotComScale;
            }
        }
    }

    private async Task<string?> PickExportPathAsync(string title, string extension, string typeDescription)
    {
        if (Application.Current?.ApplicationLifetime is not IClassicDesktopStyleApplicationLifetime desktop
            || desktop.MainWindow?.StorageProvider is not { CanSave: true } storageProvider)
        {
            StatusMessage = "Save dialog unavailable. Export aborted.";
            return null;
        }

        string normalizedExtension = extension.TrimStart('.');
        string suggested = $"DNS-Hop-Benchmark-{DateTime.Now:yyyyMMdd-HHmmss}.{normalizedExtension}";

        IStorageFile? storageFile = await storageProvider.SaveFilePickerAsync(
            new FilePickerSaveOptions
            {
                Title = title,
                SuggestedFileName = suggested,
                DefaultExtension = normalizedExtension,
                ShowOverwritePrompt = true,
                FileTypeChoices =
                [
                    new FilePickerFileType(typeDescription)
                    {
                        Patterns = [$"*.{normalizedExtension}"],
                    },
                ],
            }).ConfigureAwait(true);

        if (storageFile is null)
        {
            return null;
        }

        string? localPath = storageFile.TryGetLocalPath();
        if (!string.IsNullOrWhiteSpace(localPath))
        {
            return localPath;
        }

        // Fallback for non-local providers: write into AppData and report the effective location.
        string fallbackRoot = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(fallbackRoot))
        {
            fallbackRoot = Path.GetTempPath();
        }

        Directory.CreateDirectory(Path.Combine(fallbackRoot, "DNS Hop", "Exports"));
        return Path.Combine(fallbackRoot, "DNS Hop", "Exports", suggested);
    }

    private enum SortMode
    {
        BestPerformance,
        Cached,
        Uncached,
    }

    private static bool TryBuildProxyType(string? value, out DnsOutboundProxyType proxyType)
    {
        if (Enum.TryParse(value, ignoreCase: true, out DnsOutboundProxyType parsed))
        {
            proxyType = parsed;
            return true;
        }

        proxyType = DnsOutboundProxyType.None;
        return false;
    }
}