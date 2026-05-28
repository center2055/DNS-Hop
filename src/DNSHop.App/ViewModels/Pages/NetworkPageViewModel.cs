using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DNSHop.App.Models;
using DNSHop.App.Services;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DNSHop.App.ViewModels.Pages;

internal sealed partial class NetworkPageViewModel : PageViewModel
{
    private readonly AppServices _services;

    [ObservableProperty]
    private string _resolverName = string.Empty;

    [ObservableProperty]
    private string _resolverAddress = string.Empty;

    [ObservableProperty]
    private string _activeInterfaces = string.Empty;

    [ObservableProperty]
    private string _resolverNote = string.Empty;

    [ObservableProperty]
    private bool _isLeakTestRunning;

    [ObservableProperty]
    private string _leakTestStatus = string.Empty;

    [ObservableProperty]
    private string _leakTestLastRun = string.Empty;

    public NetworkPageViewModel(AppServices services) : base("Network", "Network.Title")
    {
        _services = services;
    }

    public ObservableCollection<CurrentDnsAdapterViewModel> Adapters { get; } = new();

    public override async void OnActivated()
    {
        await RefreshAsync().ConfigureAwait(false);
    }

    [RelayCommand]
    private async Task RefreshAsync()
    {
        try
        {
            var snapshot = await _services.CurrentDns.GetSnapshotAsync(CancellationToken.None).ConfigureAwait(false);
            await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() =>
            {
                var displayName = ResolveDisplayName(snapshot.ResolverName, snapshot.ResolverAddress);
                ResolverName = displayName;
                ResolverAddress = snapshot.ResolverAddress;
                ActiveInterfaces = snapshot.ActiveInterfaces;
                ResolverNote = snapshot.ResolverNote;

                Adapters.Clear();
                foreach (var adapter in snapshot.Adapters)
                {
                    Adapters.Add(adapter);
                }
            });
        }
        catch (Exception ex)
        {
            AppDiagnostics.WriteWarning("Network", $"Refresh failed: {ex.Message}");
        }
    }

    [RelayCommand]
    private async Task RunLeakTestAsync()
    {
        if (IsLeakTestRunning)
        {
            return;
        }

        IsLeakTestRunning = true;
        LeakTestStatus = Localization["Network.LeakTest.Running"];

        try
        {
            var expectedIps = CollectExpectedIps();
            var result = await _services.LeakTest.RunAsync(expectedIps, ResolverAddress, CancellationToken.None).ConfigureAwait(false);
            _services.AppState.LastLeakTest = result;

            await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() =>
            {
                LeakTestStatus = result.Passed
                    ? Localization["Network.LeakTest.Pass"]
                    : Localization["Network.LeakTest.Fail"];
                LeakTestLastRun = string.Format(Localization["Network.LeakTest.LastRun"], result.CheckedAt.ToLocalTime().ToString("g"));
            });
        }
        finally
        {
            IsLeakTestRunning = false;
        }
    }

    private IReadOnlyList<string> CollectExpectedIps()
    {
        var latest = _services.AppState.ApplyHistory.FirstOrDefault();
        if (latest is null)
        {
            return Array.Empty<string>();
        }

        var ips = new List<string>(4);
        if (!string.IsNullOrWhiteSpace(latest.PreferredIPv4)) { ips.Add(latest.PreferredIPv4!); }
        if (!string.IsNullOrWhiteSpace(latest.AlternateIPv4)) { ips.Add(latest.AlternateIPv4!); }
        if (!string.IsNullOrWhiteSpace(latest.PreferredIPv6)) { ips.Add(latest.PreferredIPv6!); }
        if (!string.IsNullOrWhiteSpace(latest.AlternateIPv6)) { ips.Add(latest.AlternateIPv6!); }
        return ips;
    }

    private string ResolveDisplayName(string? snapshotName, string? snapshotAddress)
    {
        // nslookup returns "UnKnown" when the resolver has no PTR record; fall back to
        // a metadata lookup or to the bare address rather than showing the literal.
        if (!string.IsNullOrWhiteSpace(snapshotName)
            && !string.Equals(snapshotName, "UnKnown", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(snapshotName, "Unknown", StringComparison.OrdinalIgnoreCase))
        {
            return snapshotName;
        }

        var meta = _services.Metadata.LookupByEndpoint(snapshotAddress, null);
        if (meta is not null && !string.IsNullOrWhiteSpace(meta.Provider))
        {
            return meta.Provider;
        }

        return string.IsNullOrWhiteSpace(snapshotAddress) ? string.Empty : snapshotAddress;
    }
}
