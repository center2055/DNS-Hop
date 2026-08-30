using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DNSHop.App.Models;
using DNSHop.App.Services;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DNSHop.App.ViewModels.Pages;

internal sealed partial class BenchmarkPageViewModel : PageViewModel
{
    private readonly AppServices _services;
    private CancellationTokenSource? _cts;
    private readonly Stopwatch _runStopwatch = new();
    private DispatcherTimer? _tickTimer;
    private int _totalServers;
    private int _queriesPerServer = 15;

    // Sliding window over the most recent progress callbacks. ETA is computed from the
    // rate of CompletedQueries between the oldest and newest sample in this window so
    // a stalled dead-server tail is reflected within seconds.
    private readonly Queue<(TimeSpan At, int Completed)> _progressSamples = new();
    private int _lastTotalQueries;
    private int _lastCompletedQueries;

    [ObservableProperty]
    private bool _isRunning;

    [ObservableProperty]
    private bool _isServerListLoading;

    [ObservableProperty]
    private string _statusMessage = string.Empty;

    [ObservableProperty]
    private int _percentCompleted;

    [ObservableProperty]
    private int _queriesRemaining;

    [ObservableProperty]
    private int _serversCompleted;

    [ObservableProperty]
    private int _serversTotal;

    [ObservableProperty]
    private string _elapsed = "00:00";

    [ObservableProperty]
    private string _eta = "—";

    [ObservableProperty]
    private int _timeoutMilliseconds = 2500;

    [ObservableProperty]
    private int _concurrencyLimit = 8;

    [ObservableProperty]
    private int _attemptsPerProbe = 3;

    [ObservableProperty]
    private bool _autoUpdateListOnStartup = true;

    [ObservableProperty]
    private string _ipVersionFilter = "Both";

    [ObservableProperty]
    private bool _enableDnssecProbe = true;

    public BenchmarkPageViewModel(AppServices services) : base("Benchmark", "Benchmark.Title")
    {
        _services = services;
        var settings = _services.Settings.Load();
        TimeoutMilliseconds = settings.TimeoutMilliseconds;
        ConcurrencyLimit = settings.ConcurrencyLimit;
        AttemptsPerProbe = settings.AttemptsPerProbe;
        AutoUpdateListOnStartup = settings.AutoUpdateListOnStartup;
        IpVersionFilter = settings.IpVersionFilter;
        EnableDnssecProbe = settings.EnableDnssecProbe;
    }

    public ObservableCollection<string> AvailableIpVersions { get; } = new() { "Both", "IPv4", "IPv6" };

    public ObservableCollection<DnsBenchmarkResult> LiveResults => _services.AppState.LastResults;

    [RelayCommand]
    private async Task StartAsync()
    {
        if (IsRunning)
        {
            return;
        }

        _cts = new CancellationTokenSource();
        IsRunning = true;
        _runStopwatch.Restart();
        StartTickTimer();
        StatusMessage = Localization["Benchmark.LoadingList"];

        try
        {
            IsServerListLoading = true;
            var settings = _services.Settings.Load();
            var baseList = await _services.ServerList.GetServersAsync(settings.AutoUpdateListOnStartup, _cts.Token).ConfigureAwait(false);
            var merged = new List<DnsServerDefinition>(baseList);
            merged.AddRange(settings.CustomServers);

            // Drop everything the user excluded on the Resolvers page so the
            // benchmark only spends time on what they actually want to test.
            var sidelined = new HashSet<string>(
                settings.SidelinedServerKeys ?? Array.Empty<string>(),
                StringComparer.OrdinalIgnoreCase);
            if (sidelined.Count > 0)
            {
                merged = merged
                    .Where(s => !sidelined.Contains($"{s.Protocol}|{s.EndpointDisplay}"))
                    .ToList();
            }

            // Address-family filter: resolvers reached by hostname are not tied to a family, so
            // they stay in the IPv4 and mixed runs; an IPv6-only run keeps just the literal
            // IPv6 endpoints.
            if (!string.Equals(IpVersionFilter, "Both", StringComparison.OrdinalIgnoreCase))
            {
                bool wantIpv6 = string.Equals(IpVersionFilter, "IPv6", StringComparison.OrdinalIgnoreCase);
                merged = merged
                    .Where(s =>
                    {
                        if (!System.Net.IPAddress.TryParse(s.AddressOrHost, out var parsed))
                        {
                            return !wantIpv6;
                        }

                        bool isIpv6 = parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
                        return isIpv6 == wantIpv6;
                    })
                    .ToList();
            }

            IsServerListLoading = false;

            if (merged.Count == 0)
            {
                StatusMessage = string.Equals(IpVersionFilter, "Both", StringComparison.OrdinalIgnoreCase)
                    ? "Every resolver is excluded. Re-include at least one on the Resolvers page."
                    : $"No resolver matches the {IpVersionFilter} filter. Choose a different IP version.";
                return;
            }

            _totalServers = merged.Count;
            _queriesPerServer = Math.Max(1, AttemptsPerProbe * 5);
            ServersTotal = _totalServers;
            ServersCompleted = 0;
            _progressSamples.Clear();
            _lastTotalQueries = 0;
            _lastCompletedQueries = 0;

            var options = new DnsBenchmarkOptions
            {
                TimeoutMilliseconds = TimeoutMilliseconds,
                ConcurrencyLimit = ConcurrencyLimit,
                AttemptsPerProbe = AttemptsPerProbe,
                EnableDnssecProbe = EnableDnssecProbe,
                OutboundProxyType = ParseProxy(settings.OutboundProxyType),
                OutboundProxyHost = settings.OutboundProxyHost,
                OutboundProxyPort = settings.OutboundProxyPort,
            };

            var progress = new Progress<DnsBenchmarkProgress>(p =>
            {
                PercentCompleted = (int)p.PercentCompleted;
                QueriesRemaining = p.QueriesRemaining;
                _lastTotalQueries = p.TotalQueries;
                _lastCompletedQueries = p.CompletedQueries;
                RecordProgressSample(p.CompletedQueries);
                if (_totalServers > 0 && p.TotalQueries > 0)
                {
                    ServersCompleted = (int)((double)p.CompletedQueries / p.TotalQueries * _totalServers);
                }
                StatusMessage = string.IsNullOrWhiteSpace(p.CurrentServer)
                    ? StatusMessage
                    : $"Testing {p.CurrentServer}  ({p.CompletedQueries}/{p.TotalQueries})";
            });

            var results = await _services.Benchmark.BenchmarkAsync(merged, options, progress, _cts.Token).ConfigureAwait(false);

            await Dispatcher.UIThread.InvokeAsync(() =>
            {
                LiveResults.Clear();
                foreach (var r in results.OrderBy(r => r.AverageMilliseconds ?? double.MaxValue))
                {
                    LiveResults.Add(r);
                }

                _services.AppState.LastBenchmarkAt = DateTimeOffset.UtcNow;
                _services.AppState.LastBenchmarkServerCount = results.Count;
                StatusMessage = $"Benchmarked {results.Count} resolvers in {_runStopwatch.Elapsed:mm\\:ss}";
                ServersCompleted = _totalServers;
                Eta = "—";

                // A finished run is only useful once you can see it, so jump straight to Results
                // rather than leaving a completed progress bar on screen. Cancelled and failed
                // runs fall through to the catch blocks below and stay where they are.
                if (results.Count > 0)
                {
                    _services.Navigator?.NavigateTo("Results");
                }
            });
        }
        catch (OperationCanceledException)
        {
            StatusMessage = Localization["Common.Cancel"];
        }
        catch (Exception ex)
        {
            StatusMessage = ex.Message;
            AppDiagnostics.WriteError("Benchmark", "Benchmark failed.", ex);
        }
        finally
        {
            IsRunning = false;
            IsServerListLoading = false;
            StopTickTimer();
            _runStopwatch.Stop();
        }
    }

    [RelayCommand]
    private void Cancel()
    {
        _cts?.Cancel();
    }

    public override void OnActivated()
    {
        // If the user navigated away during a long run and the page is now back on
        // screen, restart the UI tick. The benchmark itself never stopped — only the
        // DispatcherTimer that paints Elapsed / ETA does.
        if (IsRunning && _tickTimer is null)
        {
            StartTickTimer();
        }
    }

    public override void OnDeactivated()
    {
        // Pause the UI tick but keep the stopwatch running so Elapsed stays accurate
        // when the user comes back. Stopping the stopwatch on deactivate caused the
        // counter to freeze at whatever value it had on tab change.
        if (_tickTimer is not null)
        {
            _tickTimer.Stop();
            _tickTimer = null;
        }
    }

    private void StartTickTimer()
    {
        if (_tickTimer is not null)
        {
            _tickTimer.Stop();
            _tickTimer = null;
        }
        _tickTimer = new DispatcherTimer(
            TimeSpan.FromMilliseconds(250),
            DispatcherPriority.Background,
            (_, _) => UpdateElapsedAndEta());
        _tickTimer.Start();
    }

    private void StopTickTimer()
    {
        // The stopwatch lifecycle belongs to StartAsync; only the UI tick is
        // toggled here so navigating between pages can't pause Elapsed.
        if (_tickTimer is not null)
        {
            _tickTimer.Stop();
            _tickTimer = null;
        }
    }

    private void UpdateElapsedAndEta()
    {
        var elapsed = _runStopwatch.Elapsed;
        Elapsed = elapsed.ToString(elapsed.TotalHours >= 1 ? @"hh\:mm\:ss" : @"mm\:ss");
        Eta = ComputeEta(elapsed);
    }

    private string ComputeEta(TimeSpan elapsed)
    {
        if (_lastTotalQueries <= 0 || _lastCompletedQueries >= _lastTotalQueries)
        {
            return "—";
        }

        if (_progressSamples.Count < 2 || elapsed.TotalSeconds < 1)
        {
            return "—";
        }

        var oldest = _progressSamples.Peek();
        (TimeSpan At, int Completed) newest = (elapsed, _lastCompletedQueries);
        // The Queue exposes the head via Peek but no tail accessor; reuse the most
        // recent callback values we cached instead of iterating.

        var deltaQueries = newest.Completed - oldest.Completed;
        var deltaSeconds = (newest.At - oldest.At).TotalSeconds;
        if (deltaQueries <= 0 || deltaSeconds <= 0.05)
        {
            return "—";
        }

        var recentRate = deltaQueries / deltaSeconds; // queries per second
        var remainingQueries = _lastTotalQueries - _lastCompletedQueries;
        var remainingSeconds = remainingQueries / recentRate;
        if (double.IsNaN(remainingSeconds) || double.IsInfinity(remainingSeconds) || remainingSeconds < 0)
        {
            return "—";
        }

        var remaining = TimeSpan.FromSeconds(Math.Min(remainingSeconds, 60 * 60 * 6));
        return remaining.ToString(remaining.TotalHours >= 1 ? @"hh\:mm\:ss" : @"mm\:ss");
    }

    private void RecordProgressSample(int completed)
    {
        var sample = (_runStopwatch.Elapsed, completed);
        _progressSamples.Enqueue(sample);

        // Keep ~12 seconds of recent samples so the rate adapts quickly when the
        // benchmark hits a dead-server batch.
        while (_progressSamples.Count > 1 && (sample.Elapsed - _progressSamples.Peek().At).TotalSeconds > 12)
        {
            _progressSamples.Dequeue();
        }

        if (_progressSamples.Count > 64)
        {
            _progressSamples.Dequeue();
        }
    }

    private static DnsOutboundProxyType ParseProxy(string? raw)
    {
        return Enum.TryParse<DnsOutboundProxyType>(raw, ignoreCase: true, out var v) ? v : DnsOutboundProxyType.None;
    }

    partial void OnTimeoutMillisecondsChanged(int value) => PersistOptions();
    partial void OnConcurrencyLimitChanged(int value) => PersistOptions();
    partial void OnAttemptsPerProbeChanged(int value) => PersistOptions();
    partial void OnAutoUpdateListOnStartupChanged(bool value) => PersistOptions();

    partial void OnIpVersionFilterChanged(string value) => PersistOptions();

    partial void OnEnableDnssecProbeChanged(bool value) => PersistOptions();

    private void PersistOptions()
    {
        var current = _services.Settings.Load();
        _services.Settings.Save(new AppSettings
        {
            Theme = current.Theme,
            Language = current.Language,
            UseMica = current.UseMica,
            LastNavSection = current.LastNavSection,
            TimeoutMilliseconds = TimeoutMilliseconds,
            ConcurrencyLimit = ConcurrencyLimit,
            AttemptsPerProbe = AttemptsPerProbe,
            AutoUpdateListOnStartup = AutoUpdateListOnStartup,
            IpVersionFilter = IpVersionFilter,
            EnableDnssecProbe = EnableDnssecProbe,
            CheckForAppUpdatesOnStartup = current.CheckForAppUpdatesOnStartup,
            OutboundProxyType = current.OutboundProxyType,
            OutboundProxyHost = current.OutboundProxyHost,
            OutboundProxyPort = current.OutboundProxyPort,
            CustomServers = current.CustomServers,
            SidelinedServerKeys = current.SidelinedServerKeys,
            ActiveProfileId = current.ActiveProfileId,
            Profiles = current.Profiles,
            ApplyHistory = current.ApplyHistory,
        });
    }
}
