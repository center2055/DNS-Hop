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

public enum ResolversSortMode
{
    Region,
    Provider,
    Endpoint,
    Protocol,
}

internal sealed partial class ResolversPageViewModel : PageViewModel
{
    private readonly AppServices _services;

    [ObservableProperty]
    private string _filterText = string.Empty;

    [ObservableProperty]
    private bool _isLoading;

    [ObservableProperty]
    private ResolverItemViewModel? _selected;

    [ObservableProperty]
    private ResolversSortMode _sortMode = ResolversSortMode.Region;

    [ObservableProperty]
    private bool _noLogsOnly;

    [ObservableProperty]
    private bool _regionOnly;

    public ResolversPageViewModel(AppServices services) : base("Resolvers", "Resolvers.Title")
    {
        _services = services;
    }

    public ObservableCollection<ResolverItemViewModel> Items { get; } = new();

    public ObservableCollection<ResolverItemViewModel> Filtered { get; } = new();

    public ObservableCollection<ResolversSortMode> AvailableSortModes { get; } = new(Enum.GetValues<ResolversSortMode>());

    public override async void OnActivated()
    {
        if (Items.Count == 0)
        {
            await ReloadAsync().ConfigureAwait(false);
        }
    }

    [RelayCommand]
    private Task ReloadAsync() => LoadAsync(forceRemote: true);

    [RelayCommand]
    private async Task ApplyAsync()
    {
        if (Selected is null)
        {
            return;
        }

        var result = await _services.SystemDns.ApplyAsync(Selected.Definition, CancellationToken.None).ConfigureAwait(false);
        if (result.Success)
        {
            _services.AppState.RecordApplied(new AppliedDnsEntry
            {
                AppliedAt = DateTimeOffset.UtcNow,
                DisplayLabel = $"{Selected.Provider} ({Selected.Endpoint})",
                PreferredIPv4 = Selected.Definition.AddressOrHost,
            });
        }
    }

    partial void OnFilterTextChanged(string value) => ApplyFilter();
    partial void OnSortModeChanged(ResolversSortMode value) => ApplyFilter();
    partial void OnNoLogsOnlyChanged(bool value) => ApplyFilter();
    partial void OnRegionOnlyChanged(bool value) => ApplyFilter();

    private async Task LoadAsync(bool forceRemote)
    {
        try
        {
            IsLoading = true;
            var settings = _services.Settings.Load();
            var servers = await _services.ServerList.GetServersAsync(forceRemote || settings.AutoUpdateListOnStartup, CancellationToken.None).ConfigureAwait(false);
            var region = _services.AppState.DetectedRegion ?? _services.Geo.Region;

            Items.Clear();
            foreach (var s in servers)
            {
                var meta = _services.Metadata.LookupByEndpoint(s.AddressOrHost, s.Provider);
                Items.Add(new ResolverItemViewModel(s, meta, region));
            }
            foreach (var s in settings.CustomServers)
            {
                Items.Add(new ResolverItemViewModel(s, null, region));
            }
            ApplyFilter();
        }
        catch (Exception ex)
        {
            AppDiagnostics.WriteWarning("Resolvers", $"Load failed: {ex.Message}");
        }
        finally
        {
            IsLoading = false;
        }
    }

    private void ApplyFilter()
    {
        var needle = FilterText?.Trim();

        IEnumerable<ResolverItemViewModel> view = Items;
        if (!string.IsNullOrEmpty(needle))
        {
            view = view.Where(i => i.Matches(needle));
        }
        if (NoLogsOnly)
        {
            view = view.Where(i => i.NoLogs);
        }
        if (RegionOnly)
        {
            view = view.Where(i => i.BestForRegion);
        }

        view = SortMode switch
        {
            ResolversSortMode.Region => view
                .OrderByDescending(i => i.BestForRegion)
                .ThenBy(i => i.Provider, StringComparer.OrdinalIgnoreCase),
            ResolversSortMode.Provider => view.OrderBy(i => i.Provider, StringComparer.OrdinalIgnoreCase),
            ResolversSortMode.Endpoint => view.OrderBy(i => i.Endpoint, StringComparer.OrdinalIgnoreCase),
            ResolversSortMode.Protocol => view
                .OrderBy(i => i.Protocol, StringComparer.OrdinalIgnoreCase)
                .ThenBy(i => i.Provider, StringComparer.OrdinalIgnoreCase),
            _ => view,
        };

        Filtered.Clear();
        foreach (var item in view)
        {
            Filtered.Add(item);
        }
    }
}

internal sealed class ResolverItemViewModel
{
    public ResolverItemViewModel(DnsServerDefinition definition, ResolverMetadata? metadata, string? userRegion)
    {
        Definition = definition;
        Provider = definition.Provider;
        Endpoint = definition.EndpointDisplay;
        Protocol = definition.Protocol.ToString();
        CountryCode = metadata?.CountryCode;
        NoLogs = metadata?.NoLogs == true;
        BestForRegion = metadata is not null
            && userRegion is not null
            && metadata.Regions.Any(r => string.Equals(r, userRegion, StringComparison.OrdinalIgnoreCase) || string.Equals(r, "GLOBAL", StringComparison.OrdinalIgnoreCase));
    }

    public DnsServerDefinition Definition { get; }
    public string Provider { get; }
    public string Endpoint { get; }
    public string Protocol { get; }
    public string? CountryCode { get; }
    public bool NoLogs { get; }
    public bool BestForRegion { get; }

    public bool Matches(string needle)
    {
        return Endpoint.Contains(needle, StringComparison.OrdinalIgnoreCase)
            || Provider.Contains(needle, StringComparison.OrdinalIgnoreCase)
            || Protocol.Contains(needle, StringComparison.OrdinalIgnoreCase);
    }
}
