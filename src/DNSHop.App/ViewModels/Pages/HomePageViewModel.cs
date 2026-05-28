using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DNSHop.App.Models;
using DNSHop.App.Services;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DNSHop.App.ViewModels.Pages;

internal sealed partial class HomePageViewModel : PageViewModel
{
    private readonly AppServices _services;

    [ObservableProperty]
    private string _currentResolver = string.Empty;

    [ObservableProperty]
    private string _currentAdapter = string.Empty;

    [ObservableProperty]
    private string _activeProfileLabel = string.Empty;

    [ObservableProperty]
    private string _regionLabel = "—";

    [ObservableProperty]
    private string _lastBenchmarkLabel = string.Empty;

    [ObservableProperty]
    private bool _hasUpdate;

    [ObservableProperty]
    private string _updateLabel = string.Empty;

    [ObservableProperty]
    private string _updateUrl = string.Empty;

    [ObservableProperty]
    private string _leakTestStatus = string.Empty;

    [ObservableProperty]
    private bool _isLeakTestRunning;

    [ObservableProperty]
    private bool _canRestorePrevious;

    public HomePageViewModel(AppServices services) : base("Home", "Home.Title")
    {
        _services = services;
        _services.AppState.PropertyChanged += (_, _) => RefreshLabels();
        _services.AppState.ApplyHistory.CollectionChanged += (_, _) => RefreshLabels();
        RefreshLabels();
    }

    public override void OnActivated()
    {
        _ = RefreshCurrentDnsAsync();
        _ = DetectRegionAsync();
        _ = CheckForUpdateAsync();
        RefreshLabels();
    }

    protected override void OnLocalizationRefresh()
    {
        RefreshLabels();
    }

    [RelayCommand]
    private void GoToBenchmark()
    {
        _services.Navigator?.NavigateTo("Benchmark");
    }

    [RelayCommand]
    private async Task ApplyBestAsync()
    {
        var results = _services.AppState.LastResults.ToList();
        if (results.Count == 0)
        {
            _services.Navigator?.NavigateTo("Benchmark");
            return;
        }

        var best = results
            .Where(r => r.Status == DnsServerStatus.Alive && !r.RedirectsNxDomain && r.AverageMilliseconds is not null)
            .OrderBy(r => r.AverageMilliseconds ?? double.MaxValue)
            .FirstOrDefault();

        if (best is null)
        {
            return;
        }

        await ApplyServerAsync(best.Server).ConfigureAwait(false);
    }

    [RelayCommand]
    private async Task CheckTamperingAsync()
    {
        IsLeakTestRunning = true;
        try
        {
            var expectedIps = CollectExpectedIps();
            var result = await _services.LeakTest.RunAsync(expectedIps, CurrentResolver, System.Threading.CancellationToken.None).ConfigureAwait(false);
            _services.AppState.LastLeakTest = result;
            LeakTestStatus = result.Passed
                ? Localization["Network.LeakTest.Pass"]
                : Localization["Network.LeakTest.Fail"];
        }
        finally
        {
            IsLeakTestRunning = false;
        }
    }

    private System.Collections.Generic.IReadOnlyList<string> CollectExpectedIps()
    {
        var latest = _services.AppState.ApplyHistory.FirstOrDefault();
        if (latest is null)
        {
            return System.Array.Empty<string>();
        }

        var ips = new System.Collections.Generic.List<string>(4);
        if (!string.IsNullOrWhiteSpace(latest.PreferredIPv4)) { ips.Add(latest.PreferredIPv4!); }
        if (!string.IsNullOrWhiteSpace(latest.AlternateIPv4)) { ips.Add(latest.AlternateIPv4!); }
        if (!string.IsNullOrWhiteSpace(latest.PreferredIPv6)) { ips.Add(latest.PreferredIPv6!); }
        if (!string.IsNullOrWhiteSpace(latest.AlternateIPv6)) { ips.Add(latest.AlternateIPv6!); }
        return ips;
    }

    [RelayCommand]
    private async Task RestorePreviousAsync()
    {
        var previous = _services.AppState.PreviousApplied();
        if (previous is null)
        {
            return;
        }

        var pseudoProfile = new DnsProfile
        {
            Id = previous.ProfileId ?? "history",
            Name = previous.DisplayLabel,
            PreferredIPv4 = previous.PreferredIPv4,
            AlternateIPv4 = previous.AlternateIPv4,
            PreferredIPv6 = previous.PreferredIPv6,
            AlternateIPv6 = previous.AlternateIPv6,
        };

        try
        {
            await _services.SystemDns.ApplyProfileAsync(pseudoProfile, System.Threading.CancellationToken.None).ConfigureAwait(false);
            await RefreshCurrentDnsAsync().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            AppDiagnostics.WriteError("Home", "Restore previous DNS failed.", ex);
        }
    }

    private async Task RefreshCurrentDnsAsync()
    {
        try
        {
            var snapshot = await _services.CurrentDns.GetSnapshotAsync(CancellationToken.None).ConfigureAwait(false);
            var primary = snapshot.Adapters.FirstOrDefault(a => string.Equals(a.TrafficRole, "Active route", StringComparison.Ordinal))
                       ?? snapshot.Adapters.FirstOrDefault();

            await Dispatcher.UIThread.InvokeAsync(() =>
            {
                if (primary is null)
                {
                    CurrentResolver = Localization["Home.CurrentDns.Detecting"];
                    CurrentAdapter = string.Empty;
                    return;
                }

                CurrentResolver = string.IsNullOrWhiteSpace(snapshot.ResolverAddress) || snapshot.ResolverAddress == "Unknown"
                    ? primary.Ipv4Servers
                    : snapshot.ResolverAddress;
                CurrentAdapter = string.Format(Localization["Home.CurrentDns.Adapter"], primary.InterfaceName);
                _services.AppState.ActiveAdapterName = primary.InterfaceName;
            });
        }
        catch (Exception ex)
        {
            AppDiagnostics.WriteWarning("Home", $"Refresh current DNS failed: {ex.Message}");
        }
    }

    private async Task DetectRegionAsync()
    {
        try
        {
            var region = await _services.Geo.DetectAsync(CancellationToken.None).ConfigureAwait(false);
            await Dispatcher.UIThread.InvokeAsync(() =>
            {
                _services.AppState.DetectedRegion = region;
                RegionLabel = region;
            });
        }
        catch
        {
        }
    }

    private async Task CheckForUpdateAsync()
    {
        try
        {
            var snapshot = await _services.Releases.GetReleaseSnapshotAsync(CancellationToken.None).ConfigureAwait(false);
            var latest = snapshot.LatestStableRelease;
            if (latest?.ParsedVersion is null)
            {
                return;
            }

            if (latest.ParsedVersion > _services.Releases.CurrentVersion)
            {
                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    HasUpdate = true;
                    UpdateLabel = string.Format(Localization["Home.Update.Available"], latest.ParsedVersion.ToString(3));
                    UpdateUrl = latest.HtmlUrl;
                });
            }
        }
        catch (Exception ex)
        {
            AppDiagnostics.WriteWarning("Home", $"Update check failed: {ex.Message}");
        }
    }

    private void RefreshLabels()
    {
        var active = _services.AppState.GetActiveProfile();
        ActiveProfileLabel = active?.Name ?? Localization["Home.Profile.None"];

        var region = _services.AppState.DetectedRegion;
        if (!string.IsNullOrWhiteSpace(region))
        {
            RegionLabel = region;
        }

        if (_services.AppState.LastBenchmarkAt is DateTimeOffset when)
        {
            LastBenchmarkLabel = string.Format(
                Localization["Home.LastBenchmark.Time"],
                _services.AppState.LastBenchmarkServerCount,
                when.ToLocalTime().ToString("g"));
        }
        else
        {
            LastBenchmarkLabel = Localization["Home.LastBenchmark.Never"];
        }

        CanRestorePrevious = _services.AppState.PreviousApplied() is not null;
    }

    private async Task ApplyServerAsync(DnsServerDefinition server, bool recordHistory = true)
    {
        try
        {
            var result = await _services.SystemDns.ApplyAsync(server, CancellationToken.None).ConfigureAwait(false);
            if (result.Success && recordHistory)
            {
                _services.AppState.RecordApplied(new AppliedDnsEntry
                {
                    AppliedAt = DateTimeOffset.UtcNow,
                    DisplayLabel = $"{server.Provider} ({server.EndpointDisplay})",
                    PreferredIPv4 = server.AddressOrHost,
                });
            }
            await RefreshCurrentDnsAsync().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            AppDiagnostics.WriteError("Home", "Apply resolver failed.", ex);
        }
    }
}
