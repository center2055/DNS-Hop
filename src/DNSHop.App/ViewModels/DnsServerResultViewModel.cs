using CommunityToolkit.Mvvm.ComponentModel;
using DNSHop.App.Models;
using System.Collections.Generic;
using System.Linq;

namespace DNSHop.App.ViewModels;

public partial class DnsServerResultViewModel : ViewModelBase
{
    public DnsServerResultViewModel(DnsServerDefinition server)
    {
        Server = server;
        IsPinned = server.IsPinned;
        IsSidelined = server.IsSidelined;
        SearchKey = string.Create(
            Endpoint.Length + Provider.Length + Protocol.Length + 2,
            (Endpoint, Provider, Protocol),
            static (span, tuple) =>
            {
                int offset = 0;
                tuple.Endpoint.AsSpan().CopyTo(span[offset..]);
                offset += tuple.Endpoint.Length;
                span[offset++] = '|';
                tuple.Provider.AsSpan().CopyTo(span[offset..]);
                offset += tuple.Provider.Length;
                span[offset++] = '|';
                tuple.Protocol.AsSpan().CopyTo(span[offset..]);
            }).ToLowerInvariant();
    }

    public DnsServerDefinition Server { get; }

    public string Endpoint => Server.EndpointDisplay;

    public string Provider => Server.Provider;

    public string Protocol => Server.Protocol.ToString().ToUpperInvariant();

    public string SearchKey { get; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(AverageMilliseconds))]
    [NotifyPropertyChangedFor(nameof(ProbeSummary))]
    private double? cachedMilliseconds;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(AverageMilliseconds))]
    [NotifyPropertyChangedFor(nameof(ProbeSummary))]
    private double? uncachedMilliseconds;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(AverageMilliseconds))]
    [NotifyPropertyChangedFor(nameof(ProbeSummary))]
    private double? dotComMilliseconds;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StatusLabel))]
    [NotifyPropertyChangedFor(nameof(IsAlive))]
    private DnsServerStatus status = DnsServerStatus.Unknown;

    [ObservableProperty]
    private bool supportsDnssec;

    [ObservableProperty]
    private bool redirectsNxDomain;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ProbeSummary))]
    private double poisoningConfidence;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ProbeSummary))]
    private string? poisoningEvidence;

    [ObservableProperty]
    private int successfulQueries;

    [ObservableProperty]
    private int failedQueries;

    [ObservableProperty]
    private string? lastError;

    [ObservableProperty]
    private bool isPinned;

    [ObservableProperty]
    private bool isSidelined;

    [ObservableProperty]
    private double cachedScaleMaximum = 120;

    [ObservableProperty]
    private double uncachedScaleMaximum = 250;

    [ObservableProperty]
    private double dotComScaleMaximum = 120;

    public string StatusLabel => Status switch
    {
        DnsServerStatus.Alive => "Alive",
        DnsServerStatus.Dead => "Dead",
        DnsServerStatus.Redirecting => "Hijacking",
        _ => "Unknown",
    };

    public bool IsAlive => Status == DnsServerStatus.Alive;

    public double? AverageMilliseconds
    {
        get
        {
            // Only show an average when all core probes succeeded.
            if (CachedMilliseconds is null || UncachedMilliseconds is null || DotComMilliseconds is null)
            {
                return null;
            }

            List<double> values = [CachedMilliseconds.Value, UncachedMilliseconds.Value, DotComMilliseconds.Value];
            return values.Average();
        }
    }

    public string ProbeSummary =>
        $"Cached: {FormatMs(CachedMilliseconds)} | Uncached: {FormatMs(UncachedMilliseconds)} | DotCom: {FormatMs(DotComMilliseconds)} | Avg: {FormatMs(AverageMilliseconds)} | Poisoning: {PoisoningConfidence:P0}"
        + (string.IsNullOrWhiteSpace(PoisoningEvidence) ? string.Empty : $" | {PoisoningEvidence}");

    public void ApplyBenchmarkResult(DnsBenchmarkResult result)
    {
        CachedMilliseconds = result.CachedMilliseconds;
        UncachedMilliseconds = result.UncachedMilliseconds;
        DotComMilliseconds = result.DotComMilliseconds;
        Status = result.Status;
        SupportsDnssec = result.SupportsDnssec;
        RedirectsNxDomain = result.RedirectsNxDomain;
        PoisoningConfidence = result.PoisoningConfidence;
        PoisoningEvidence = result.PoisoningEvidence;
        SuccessfulQueries = result.SuccessfulQueries;
        FailedQueries = result.FailedQueries;
        LastError = result.LastError;
    }

    public DnsBenchmarkResult ToResultModel()
    {
        return new DnsBenchmarkResult
        {
            Server = Server,
            CachedMilliseconds = CachedMilliseconds,
            UncachedMilliseconds = UncachedMilliseconds,
            DotComMilliseconds = DotComMilliseconds,
            Status = Status,
            SupportsDnssec = SupportsDnssec,
            RedirectsNxDomain = RedirectsNxDomain,
            PoisoningConfidence = PoisoningConfidence,
            PoisoningEvidence = PoisoningEvidence,
            SuccessfulQueries = SuccessfulQueries,
            FailedQueries = FailedQueries,
            LastError = LastError,
        };
    }

    partial void OnIsPinnedChanged(bool value)
    {
        Server.IsPinned = value;
    }

    partial void OnIsSidelinedChanged(bool value)
    {
        Server.IsSidelined = value;
    }

    public bool MatchesFilter(string normalizedTerm)
    {
        if (string.IsNullOrWhiteSpace(normalizedTerm))
        {
            return true;
        }

        return SearchKey.Contains(normalizedTerm, System.StringComparison.Ordinal);
    }

    private static string FormatMs(double? value)
        => value is null ? "n/a" : $"{value:0.0} ms";
}

