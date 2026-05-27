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

    public ResultsPageViewModel(AppServices services) : base("Results", "Results.Title")
    {
        _services = services;
        _services.AppState.LastResults.CollectionChanged += (_, _) => Refresh();
    }

    public ObservableCollection<DnsBenchmarkResult> Results => _services.AppState.LastResults;

    public ObservableCollection<ResolverRowViewModel> Rows { get; } = new();

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
            var path = await _services.Export.ExportChartToClipboardAsync(Results.ToList(), CancellationToken.None).ConfigureAwait(false);
            ExportStatus = path;
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

        Rows.Clear();
        foreach (var r in Results.OrderBy(r => r.AverageMilliseconds ?? double.MaxValue))
        {
            Rows.Add(new ResolverRowViewModel(r, range, fastest));
        }

        OnPropertyChanged(nameof(HasResults));
    }
}

internal sealed class ResolverRowViewModel
{
    public ResolverRowViewModel(DnsBenchmarkResult result, double range, double fastest)
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

        var fillFraction = result.AverageMilliseconds is double avg && range > 0
            ? Math.Clamp(1.0 - (avg - fastest) / range, 0.0, 1.0)
            : 0.0;
        LatencyFraction = fillFraction;

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
    public double LatencyFraction { get; }
    public bool IsHealthy { get; }
    public bool IsRedirecting { get; }
    public bool IsDead { get; }
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
