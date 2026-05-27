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

    public BenchmarkPageViewModel(AppServices services) : base("Benchmark", "Benchmark.Title")
    {
        _services = services;
        var settings = _services.Settings.Load();
        TimeoutMilliseconds = settings.TimeoutMilliseconds;
        ConcurrencyLimit = settings.ConcurrencyLimit;
        AttemptsPerProbe = settings.AttemptsPerProbe;
        AutoUpdateListOnStartup = settings.AutoUpdateListOnStartup;
    }

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
            IsServerListLoading = false;

            _totalServers = merged.Count;
            _queriesPerServer = Math.Max(1, AttemptsPerProbe * 5);
            ServersTotal = _totalServers;
            ServersCompleted = 0;

            var options = new DnsBenchmarkOptions
            {
                TimeoutMilliseconds = TimeoutMilliseconds,
                ConcurrencyLimit = ConcurrencyLimit,
                AttemptsPerProbe = AttemptsPerProbe,
                OutboundProxyType = ParseProxy(settings.OutboundProxyType),
                OutboundProxyHost = settings.OutboundProxyHost,
                OutboundProxyPort = settings.OutboundProxyPort,
            };

            var progress = new Progress<DnsBenchmarkProgress>(p =>
            {
                PercentCompleted = (int)p.PercentCompleted;
                QueriesRemaining = p.QueriesRemaining;
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
        }
    }

    [RelayCommand]
    private void Cancel()
    {
        _cts?.Cancel();
    }

    public override void OnDeactivated()
    {
        StopTickTimer();
    }

    private void StartTickTimer()
    {
        StopTickTimer();
        _tickTimer = new DispatcherTimer(
            TimeSpan.FromMilliseconds(250),
            DispatcherPriority.Background,
            (_, _) => UpdateElapsedAndEta());
        _tickTimer.Start();
    }

    private void StopTickTimer()
    {
        if (_tickTimer is null)
        {
            return;
        }

        _tickTimer.Stop();
        _tickTimer = null;
        _runStopwatch.Stop();
    }

    private void UpdateElapsedAndEta()
    {
        var elapsed = _runStopwatch.Elapsed;
        Elapsed = elapsed.ToString(elapsed.TotalHours >= 1 ? @"hh\:mm\:ss" : @"mm\:ss");

        if (PercentCompleted is > 0 and < 100 && elapsed.TotalSeconds > 1)
        {
            var totalEstimate = elapsed.TotalSeconds * 100.0 / PercentCompleted;
            var remaining = TimeSpan.FromSeconds(Math.Max(0, totalEstimate - elapsed.TotalSeconds));
            Eta = remaining.ToString(remaining.TotalHours >= 1 ? @"hh\:mm\:ss" : @"mm\:ss");
        }
        else
        {
            Eta = "—";
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
            CheckForAppUpdatesOnStartup = current.CheckForAppUpdatesOnStartup,
            OutboundProxyType = current.OutboundProxyType,
            OutboundProxyHost = current.OutboundProxyHost,
            OutboundProxyPort = current.OutboundProxyPort,
            CustomServers = current.CustomServers,
            ActiveProfileId = current.ActiveProfileId,
            Profiles = current.Profiles,
            ApplyHistory = current.ApplyHistory,
        });
    }
}
