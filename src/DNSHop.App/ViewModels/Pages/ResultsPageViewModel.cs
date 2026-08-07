using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
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

public enum ResultsSortMode
{
    Best,
    Average,
    Cached,
    Uncached,
    DotCom,
    Provider,
    Protocol,
    Dnssec,
    Status,
}

internal sealed partial class ResultsPageViewModel : PageViewModel
{
    private readonly AppServices _services;

    [ObservableProperty]
    private string _exportStatus = string.Empty;

    [ObservableProperty]
    private ResolverPickViewModel? _primaryPick;

    [ObservableProperty]
    private ResolverPickViewModel? _secondaryPick;

    [ObservableProperty]
    private int _aliveCount;

    [ObservableProperty]
    private int _totalCount;

    [ObservableProperty]
    private int _dnssecCount;

    [ObservableProperty]
    private int _redirectingCount;

    [ObservableProperty]
    private ResultsSortMode _sortMode = ResultsSortMode.Best;

    [ObservableProperty]
    private bool _hideDead;

    [ObservableProperty]
    private bool _hideRedirecting;

    [ObservableProperty]
    private bool _dnssecOnly;

    [ObservableProperty]
    private bool _hidePoisoned;

    [ObservableProperty]
    private string _searchText = string.Empty;

    public ResultsPageViewModel(AppServices services) : base("Results", "Results.Title")
    {
        _services = services;
        _services.AppState.LastResults.CollectionChanged += (_, _) => Refresh();
    }

    public ObservableCollection<DnsBenchmarkResult> Results => _services.AppState.LastResults;

    public ObservableCollection<ResolverRowViewModel> Rows { get; } = new();

    public ObservableCollection<ResultsSortMode> AvailableSortModes { get; } = new(Enum.GetValues<ResultsSortMode>());

    public bool HasResults => Results.Count > 0;

    [RelayCommand]
    private async Task ExportCsvAsync()
    {
        if (!HasResults) { return; }
        try
        {
            var path = await _services.Export.ExportCsvAsync(Results.ToList(), CancellationToken.None).ConfigureAwait(false);
            ExportStatus = path;
        }
        catch (Exception ex)
        {
            ExportStatus = ex.Message;
        }
    }

    [RelayCommand]
    private async Task ExportJsonAsync()
    {
        if (!HasResults) { return; }
        try
        {
            var path = await _services.Export.ExportJsonAsync(Results.ToList(), CancellationToken.None).ConfigureAwait(false);
            ExportStatus = path;
        }
        catch (Exception ex)
        {
            ExportStatus = ex.Message;
        }
    }

    [RelayCommand]
    private async Task CopyChartAsync()
    {
        if (!HasResults) { return; }
        try
        {
            var copied = await _services.Export.CopyChartToClipboardAsync(Results.ToList(), CancellationToken.None).ConfigureAwait(false);
            ExportStatus = copied ? "Chart copied to clipboard." : "Clipboard is unavailable on this platform.";
        }
        catch (Exception ex)
        {
            ExportStatus = ex.Message;
        }
    }

    [RelayCommand]
    private async Task ApplyRowAsync(ResolverRowViewModel? row)
    {
        if (row is null)
        {
            return;
        }

        var result = await _services.SystemDns.ApplyAsync(row.Server, CancellationToken.None).ConfigureAwait(false);
        if (result.Success)
        {
            _services.AppState.RecordApplied(new AppliedDnsEntry
            {
                AppliedAt = DateTimeOffset.UtcNow,
                DisplayLabel = $"{row.Provider} ({row.Endpoint})",
                PreferredIPv4 = row.Server.AddressOrHost,
            });
        }
    }

    public override void OnActivated() => Refresh();

    partial void OnSortModeChanged(ResultsSortMode value) => Refresh();
    partial void OnHideDeadChanged(bool value) => Refresh();
    partial void OnHideRedirectingChanged(bool value) => Refresh();
    partial void OnDnssecOnlyChanged(bool value) => Refresh();
    partial void OnHidePoisonedChanged(bool value) => Refresh();
    partial void OnSearchTextChanged(string value) => Refresh();

    private void Refresh()
    {
        TotalCount = Results.Count;
        AliveCount = Results.Count(r => r.Status == DnsServerStatus.Alive);
        DnssecCount = Results.Count(r => r.SupportsDnssec);
        RedirectingCount = Results.Count(r => r.Status == DnsServerStatus.Redirecting);

        var eligible = Results
            .Where(r => r.Status == DnsServerStatus.Alive && !r.RedirectsNxDomain && r.AverageMilliseconds is not null)
            .OrderBy(r => r.AverageMilliseconds ?? double.MaxValue)
            .ToArray();

        PrimaryPick = eligible.Length > 0 ? new ResolverPickViewModel(eligible[0], _services) : null;

        var secondary = eligible.Skip(1)
            .FirstOrDefault(r => !string.Equals(r.Server.Provider, eligible[0]?.Server.Provider, StringComparison.OrdinalIgnoreCase));
        secondary ??= eligible.Length > 1 ? eligible[1] : null;
        SecondaryPick = secondary is not null ? new ResolverPickViewModel(secondary, _services) : null;

        var fastest = eligible.Length > 0 ? eligible[0].AverageMilliseconds ?? 0 : 0;
        var slowest = eligible.LastOrDefault()?.AverageMilliseconds ?? 1;
        var range = Math.Max(slowest - fastest, 1);

        IEnumerable<DnsBenchmarkResult> filtered = Results;
        if (HideDead) { filtered = filtered.Where(r => r.Status != DnsServerStatus.Dead); }
        if (HideRedirecting) { filtered = filtered.Where(r => r.Status != DnsServerStatus.Redirecting && !r.RedirectsNxDomain); }
        if (DnssecOnly) { filtered = filtered.Where(r => r.SupportsDnssec); }
        if (HidePoisoned) { filtered = filtered.Where(r => r.PoisoningConfidence < 0.5); }

        if (!string.IsNullOrWhiteSpace(SearchText))
        {
            var term = SearchText.Trim();
            filtered = filtered.Where(r =>
                r.Server.Provider.Contains(term, StringComparison.OrdinalIgnoreCase)
                || r.Server.EndpointDisplay.Contains(term, StringComparison.OrdinalIgnoreCase)
                || r.Server.AddressOrHost.Contains(term, StringComparison.OrdinalIgnoreCase)
                || r.Server.Protocol.ToString().Contains(term, StringComparison.OrdinalIgnoreCase));
        }

        var ordered = SortMode switch
        {
            ResultsSortMode.Best => filtered
                .OrderByDescending(r => r.Status == DnsServerStatus.Alive && !r.RedirectsNxDomain)
                .ThenBy(r => r.AverageMilliseconds ?? double.MaxValue),
            ResultsSortMode.Average => filtered.OrderBy(r => r.AverageMilliseconds ?? double.MaxValue),
            ResultsSortMode.Cached => filtered.OrderBy(r => r.CachedMilliseconds ?? double.MaxValue),
            ResultsSortMode.Uncached => filtered.OrderBy(r => r.UncachedMilliseconds ?? double.MaxValue),
            ResultsSortMode.DotCom => filtered.OrderBy(r => r.DotComMilliseconds ?? double.MaxValue),
            ResultsSortMode.Provider => filtered.OrderBy(r => r.Server.Provider, StringComparer.OrdinalIgnoreCase),
            ResultsSortMode.Protocol => filtered
                .OrderBy(r => r.Server.Protocol.ToString(), StringComparer.OrdinalIgnoreCase)
                .ThenBy(r => r.AverageMilliseconds ?? double.MaxValue),
            ResultsSortMode.Dnssec => filtered
                .OrderByDescending(r => r.SupportsDnssec)
                .ThenBy(r => r.AverageMilliseconds ?? double.MaxValue),
            ResultsSortMode.Status => filtered.OrderBy(r => StatusOrder(r)),
            _ => filtered.OrderBy(r => r.AverageMilliseconds ?? double.MaxValue),
        };

        Rows.Clear();
        var orderedList = ordered.ToList();

        // Shared scale so the red/green/blue bars are comparable across every row.
        double scaleMs = orderedList
            .SelectMany(r => new[] { r.CachedMilliseconds, r.UncachedMilliseconds, r.DotComMilliseconds })
            .Where(v => v is not null)
            .Select(v => v!.Value)
            .DefaultIfEmpty(1)
            .Max();
        if (scaleMs <= 0) { scaleMs = 1; }

        foreach (var r in orderedList)
        {
            Rows.Add(new ResolverRowViewModel(r, range, fastest, scaleMs));
        }

        OnPropertyChanged(nameof(HasResults));
    }

    private static int StatusOrder(DnsBenchmarkResult r)
    {
        if (r.Status == DnsServerStatus.Alive && !r.RedirectsNxDomain) { return 0; }
        if (r.Status == DnsServerStatus.Alive) { return 1; }
        if (r.Status == DnsServerStatus.Redirecting) { return 2; }
        if (r.Status == DnsServerStatus.Dead) { return 3; }
        return 4;
    }
}

internal sealed partial class ResolverRowViewModel
{
    public ResolverRowViewModel(DnsBenchmarkResult result, double range, double fastest, double scaleMs)
    {
        Server = result.Server;
        Provider = result.Server.Provider;
        Endpoint = result.Server.EndpointDisplay;
        Protocol = result.Server.Protocol.ToString();
        Status = result.Status;
        StatusLabel = result.Status.ToString();
        SupportsDnssec = result.SupportsDnssec;
        AverageMs = result.AverageMilliseconds;
        AverageDisplay = result.AverageMilliseconds is double v ? $"{v:F0} ms" : "—";
        CachedMs = result.CachedMilliseconds;
        CachedDisplay = result.CachedMilliseconds is double c ? $"{c:F0} ms" : "—";
        UncachedMs = result.UncachedMilliseconds;
        UncachedDisplay = result.UncachedMilliseconds is double u ? $"{u:F0} ms" : "—";
        DotComMs = result.DotComMilliseconds;
        DotComDisplay = result.DotComMilliseconds is double d ? $"{d:F0} ms" : "—";

        var fillFraction = result.AverageMilliseconds is double avg && range > 0
            ? Math.Clamp(1.0 - (avg - fastest) / range, 0.0, 1.0)
            : 0.0;
        LatencyFraction = fillFraction;

        // GRC-style bar lengths: longer bar = slower probe, scaled against the slowest probe on screen.
        CachedFraction = result.CachedMilliseconds is double cms && scaleMs > 0 ? Math.Clamp(cms / scaleMs, 0.0, 1.0) : 0.0;
        UncachedFraction = result.UncachedMilliseconds is double ums && scaleMs > 0 ? Math.Clamp(ums / scaleMs, 0.0, 1.0) : 0.0;
        DotComFraction = result.DotComMilliseconds is double dms && scaleMs > 0 ? Math.Clamp(dms / scaleMs, 0.0, 1.0) : 0.0;

        IsHealthy = result.Status == DnsServerStatus.Alive && !result.RedirectsNxDomain;
        IsRedirecting = result.Status == DnsServerStatus.Redirecting || result.RedirectsNxDomain;
        IsDead = result.Status == DnsServerStatus.Dead;
    }

    public DnsServerDefinition Server { get; }
    public string Provider { get; }
    public string Endpoint { get; }
    public string Protocol { get; }
    public DnsServerStatus Status { get; }
    public string StatusLabel { get; }
    public bool SupportsDnssec { get; }
    public double? AverageMs { get; }
    public string AverageDisplay { get; }
    public double? CachedMs { get; }
    public string CachedDisplay { get; }
    public double? UncachedMs { get; }
    public string UncachedDisplay { get; }
    public double? DotComMs { get; }
    public string DotComDisplay { get; }
    public double LatencyFraction { get; }
    public double CachedFraction { get; }
    public double UncachedFraction { get; }
    public double DotComFraction { get; }
    public bool IsHealthy { get; }
    public bool IsRedirecting { get; }
    public bool IsDead { get; }

    [RelayCommand]
    private Task CopyAddress() => CopyToClipboardAsync(Server.AddressOrHost);

    [RelayCommand]
    private Task CopyEndpoint() => CopyToClipboardAsync(Endpoint);

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

internal sealed class ResolverPickViewModel
{
    public ResolverPickViewModel(DnsBenchmarkResult result, AppServices services)
    {
        Server = result.Server;
        Provider = result.Server.Provider;
        Endpoint = result.Server.EndpointDisplay;
        Protocol = result.Server.Protocol.ToString();
        AverageDisplay = result.AverageMilliseconds is double v ? $"{v:F1} ms" : "—";
        SupportsDnssec = result.SupportsDnssec;

        var meta = services.Metadata.LookupByEndpoint(result.Server.AddressOrHost, result.Server.Provider);
        NoLogs = meta?.NoLogs == true;
        CountryCode = meta?.CountryCode;
    }

    public DnsServerDefinition Server { get; }
    public string Provider { get; }
    public string Endpoint { get; }
    public string Protocol { get; }
    public string AverageDisplay { get; }
    public bool SupportsDnssec { get; }
    public bool NoLogs { get; }
    public string? CountryCode { get; }
}
