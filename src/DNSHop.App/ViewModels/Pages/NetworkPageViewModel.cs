using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DNSHop.App.Models;
using DNSHop.App.Services;
using System;
using System.Collections.ObjectModel;
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
                ResolverName = snapshot.ResolverName;
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
            var result = await _services.LeakTest.RunAsync(ResolverAddress, CancellationToken.None).ConfigureAwait(false);
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
}
