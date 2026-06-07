using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DNSHop.App.Models;
using DNSHop.App.Services;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Net;
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

public enum CustomDnsProtocol
{
    UdpTcp,
    Doh,
    Dot,
    Doq,
}

internal sealed partial class ResolversPageViewModel : PageViewModel
{
    private readonly AppServices _services;
    private readonly HashSet<string> _sidelinedKeys = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _pinnedKeys = new(StringComparer.OrdinalIgnoreCase);

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

    [ObservableProperty]
    private bool _includedOnly;

    [ObservableProperty]
    private bool _isAdding;

    [ObservableProperty]
    private CustomDnsDraft? _draft;

    [ObservableProperty]
    private string _addError = string.Empty;

    public ResolversPageViewModel(AppServices services) : base("Resolvers", "Resolvers.Title")
    {
        _services = services;
    }

    public ObservableCollection<ResolverItemViewModel> Items { get; } = new();

    public ObservableCollection<ResolverItemViewModel> Filtered { get; } = new();

    public ObservableCollection<ResolversSortMode> AvailableSortModes { get; } = new(Enum.GetValues<ResolversSortMode>());

    public ObservableCollection<CustomDnsProtocol> AvailableProtocols { get; } = new(Enum.GetValues<CustomDnsProtocol>());

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

    [RelayCommand]
    private void StartAddCustom()
    {
        Draft = new CustomDnsDraft
        {
            Protocol = CustomDnsProtocol.UdpTcp,
            Provider = "Custom DNS",
            Port = 53,
        };
        AddError = string.Empty;
        IsAdding = true;
    }

    [RelayCommand]
    private void CancelAddCustom()
    {
        IsAdding = false;
        Draft = null;
        AddError = string.Empty;
    }

    [RelayCommand]
    private void SaveCustom()
    {
        if (Draft is null)
        {
            return;
        }

        if (!TryBuildCustomServer(Draft, out var server, out var error))
        {
            AddError = error;
            return;
        }

        server.IsCustom = true;

        var current = _services.Settings.Load();
        var existing = (current.CustomServers ?? Array.Empty<DnsServerDefinition>()).ToList();
        var key = BuildServerKey(server);
        if (existing.Any(s => string.Equals(BuildServerKey(s), key, StringComparison.OrdinalIgnoreCase)))
        {
            AddError = "An endpoint with this address is already in your custom list.";
            return;
        }
        existing.Add(server);

        Persist(current, existing.ToArray());

        Items.Add(BuildItem(server, isCustom: true));
        ApplyFilter();

        IsAdding = false;
        Draft = null;
        AddError = string.Empty;
    }

    [RelayCommand]
    private void RemoveCustom(ResolverItemViewModel? item)
    {
        if (item is null || !item.IsCustom)
        {
            return;
        }

        var current = _services.Settings.Load();
        var key = BuildServerKey(item.Definition);
        var remaining = (current.CustomServers ?? Array.Empty<DnsServerDefinition>())
            .Where(s => !string.Equals(BuildServerKey(s), key, StringComparison.OrdinalIgnoreCase))
            .ToArray();

        Persist(current, remaining);
        Items.Remove(item);
        ApplyFilter();
    }

    [RelayCommand]
    private void ToggleSelectedSideline()
    {
        if (Selected is null)
        {
            return;
        }

        Selected.IsSidelined = !Selected.IsSidelined;
    }

    partial void OnFilterTextChanged(string value) => ApplyFilter();
    partial void OnSortModeChanged(ResolversSortMode value) => ApplyFilter();
    partial void OnNoLogsOnlyChanged(bool value) => ApplyFilter();
    partial void OnRegionOnlyChanged(bool value) => ApplyFilter();
    partial void OnIncludedOnlyChanged(bool value) => ApplyFilter();

    private async Task LoadAsync(bool forceRemote)
    {
        try
        {
            IsLoading = true;
            var settings = _services.Settings.Load();
            _sidelinedKeys.Clear();
            foreach (var k in settings.SidelinedServerKeys ?? Array.Empty<string>())
            {
                _sidelinedKeys.Add(k);
            }

            var servers = await _services.ServerList.GetServersAsync(forceRemote || settings.AutoUpdateListOnStartup, CancellationToken.None).ConfigureAwait(false);
            var region = _services.AppState.DetectedRegion ?? _services.Geo.Region;

            UnhookItems();
            Items.Clear();
            foreach (var s in servers)
            {
                Items.Add(BuildItem(s, isCustom: false, region));
            }
            foreach (var s in settings.CustomServers ?? Array.Empty<DnsServerDefinition>())
            {
                Items.Add(BuildItem(s, isCustom: true, region));
            }
            HookItems();

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

    private ResolverItemViewModel BuildItem(DnsServerDefinition definition, bool isCustom, string? region = null)
    {
        var meta = _services.Metadata.LookupByEndpoint(definition.AddressOrHost, definition.Provider);
        var effectiveRegion = region ?? _services.AppState.DetectedRegion ?? _services.Geo.Region;
        var item = new ResolverItemViewModel(definition, meta, effectiveRegion)
        {
            IsCustom = isCustom,
        };
        var key = BuildServerKey(definition);
        item.IsSidelined = _sidelinedKeys.Contains(key);
        item.IsPinned = _pinnedKeys.Contains(key);
        return item;
    }

    private void HookItems()
    {
        foreach (var item in Items)
        {
            item.PropertyChanged += OnItemPropertyChanged;
        }
    }

    private void UnhookItems()
    {
        foreach (var item in Items)
        {
            item.PropertyChanged -= OnItemPropertyChanged;
        }
    }

    private void OnItemPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (sender is not ResolverItemViewModel item)
        {
            return;
        }

        if (string.Equals(e.PropertyName, nameof(ResolverItemViewModel.IsPinned), StringComparison.Ordinal))
        {
            var pinKey = BuildServerKey(item.Definition);
            if (item.IsPinned)
            {
                _pinnedKeys.Add(pinKey);
            }
            else
            {
                _pinnedKeys.Remove(pinKey);
            }

            ApplyFilter();
            return;
        }

        if (!string.Equals(e.PropertyName, nameof(ResolverItemViewModel.IsSidelined), StringComparison.Ordinal))
        {
            return;
        }

        var key = BuildServerKey(item.Definition);
        if (item.IsSidelined)
        {
            _sidelinedKeys.Add(key);
        }
        else
        {
            _sidelinedKeys.Remove(key);
        }

        PersistSidelines();
        if (IncludedOnly)
        {
            ApplyFilter();
        }
    }

    private void PersistSidelines()
    {
        var current = _services.Settings.Load();
        Persist(current, current.CustomServers, _sidelinedKeys.ToArray());
    }

    private void Persist(AppSettings current, DnsServerDefinition[] customServers, string[]? sidelinedOverride = null)
    {
        _services.Settings.Save(new AppSettings
        {
            Theme = current.Theme,
            Language = current.Language,
            UseMica = current.UseMica,
            LastNavSection = current.LastNavSection,
            TimeoutMilliseconds = current.TimeoutMilliseconds,
            ConcurrencyLimit = current.ConcurrencyLimit,
            AttemptsPerProbe = current.AttemptsPerProbe,
            AutoUpdateListOnStartup = current.AutoUpdateListOnStartup,
            CheckForAppUpdatesOnStartup = current.CheckForAppUpdatesOnStartup,
            OutboundProxyType = current.OutboundProxyType,
            OutboundProxyHost = current.OutboundProxyHost,
            OutboundProxyPort = current.OutboundProxyPort,
            CustomServers = customServers,
            SidelinedServerKeys = sidelinedOverride ?? current.SidelinedServerKeys,
            ActiveProfileId = current.ActiveProfileId,
            Profiles = current.Profiles,
            ApplyHistory = current.ApplyHistory,
        });
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
        if (IncludedOnly)
        {
            view = view.Where(i => !i.IsSidelined);
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

        // Pinned resolvers always float to the top. OrderBy is stable, so the
        // active sort order is preserved within the pinned and unpinned groups.
        view = view.OrderByDescending(i => i.IsPinned);

        Filtered.Clear();
        foreach (var item in view)
        {
            Filtered.Add(item);
        }
    }

    private static bool TryBuildCustomServer(CustomDnsDraft draft, out DnsServerDefinition server, out string error)
    {
        server = default!;
        error = string.Empty;
        var provider = string.IsNullOrWhiteSpace(draft.Provider) ? "Custom DNS" : draft.Provider!.Trim();

        switch (draft.Protocol)
        {
            case CustomDnsProtocol.UdpTcp:
            {
                var addr = (draft.Endpoint ?? string.Empty).Trim();
                if (!IPAddress.TryParse(addr, out var _))
                {
                    error = "Enter a valid IPv4 or IPv6 address (e.g. 1.1.1.1).";
                    return false;
                }
                var port = draft.Port is >= 1 and <= 65535 ? draft.Port : 53;
                server = DnsServerDefinition.CreateUdpTcp(addr, provider, port);
                return true;
            }
            case CustomDnsProtocol.Doh:
            {
                var url = (draft.Endpoint ?? string.Empty).Trim();
                if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)
                    || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
                {
                    error = "Enter a full https:// URL (e.g. https://cloudflare-dns.com/dns-query).";
                    return false;
                }
                server = DnsServerDefinition.CreateDoh(uri.AbsoluteUri, provider);
                return true;
            }
            case CustomDnsProtocol.Dot:
            {
                var addr = (draft.Endpoint ?? string.Empty).Trim();
                if (string.IsNullOrWhiteSpace(addr))
                {
                    error = "Enter the DoT endpoint hostname or IP.";
                    return false;
                }
                var tls = string.IsNullOrWhiteSpace(draft.DotTlsHost) ? addr : draft.DotTlsHost!.Trim();
                var port = draft.Port is >= 1 and <= 65535 ? draft.Port : 853;
                server = DnsServerDefinition.CreateDot(addr, tls, provider, port);
                return true;
            }
            case CustomDnsProtocol.Doq:
            {
                var host = (draft.Endpoint ?? string.Empty).Trim();
                if (string.IsNullOrWhiteSpace(host))
                {
                    error = "Enter the DoQ endpoint hostname or IP (e.g. dns.adguard-dns.com).";
                    return false;
                }
                var tls = string.IsNullOrWhiteSpace(draft.DotTlsHost) ? host : draft.DotTlsHost!.Trim();
                var port = draft.Port is >= 1 and <= 65535 ? draft.Port : 853;
                server = DnsServerDefinition.CreateDoq(host, provider, tls, port);
                return true;
            }
        }

        error = "Unsupported protocol.";
        return false;
    }

    private static string BuildServerKey(DnsServerDefinition s)
        => $"{s.Protocol}|{s.EndpointDisplay}";
}

internal sealed partial class ResolverItemViewModel : ObservableObject
{
    [ObservableProperty]
    private bool _isSidelined;

    [ObservableProperty]
    private bool _isPinned;

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
    public bool IsCustom { get; init; }

    public bool Matches(string needle)
    {
        return Endpoint.Contains(needle, StringComparison.OrdinalIgnoreCase)
            || Provider.Contains(needle, StringComparison.OrdinalIgnoreCase)
            || Protocol.Contains(needle, StringComparison.OrdinalIgnoreCase);
    }

    [RelayCommand]
    private void TogglePin() => IsPinned = !IsPinned;

    [RelayCommand]
    private Task CopyAddress() => CopyToClipboardAsync(Definition.AddressOrHost);

    [RelayCommand]
    private Task CopyProvider() => CopyToClipboardAsync(Provider);

    private static async Task CopyToClipboardAsync(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return;
        }

        if (Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop
            && desktop.MainWindow?.Clipboard is { } clipboard)
        {
            await clipboard.SetTextAsync(text).ConfigureAwait(false);
        }
    }
}

public sealed partial class CustomDnsDraft : ObservableObject
{
    [ObservableProperty]
    private CustomDnsProtocol _protocol = CustomDnsProtocol.UdpTcp;

    [ObservableProperty]
    private string? _provider = "Custom DNS";

    [ObservableProperty]
    private string? _endpoint;

    [ObservableProperty]
    private int _port = 53;

    [ObservableProperty]
    private string? _dotTlsHost;
}
