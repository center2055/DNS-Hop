using CommunityToolkit.Mvvm.ComponentModel;
using DNSHop.App.Models;
using DNSHop.App.Utilities;
using System.Collections.Generic;
using System.Linq;

namespace DNSHop.App.ViewModels;

public partial class DnsServerResultViewModel : ViewModelBase
{
    public event Action<DnsServerResultViewModel>? SidelinedChanged;

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
    [NotifyPropertyChangedFor(nameof(CachedDisplay))]
    [NotifyPropertyChangedFor(nameof(AverageDisplay))]
    [NotifyPropertyChangedFor(nameof(ProbeSummary))]
    private double? cachedMilliseconds;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(AverageMilliseconds))]
    [NotifyPropertyChangedFor(nameof(UncachedDisplay))]
    [NotifyPropertyChangedFor(nameof(AverageDisplay))]
    [NotifyPropertyChangedFor(nameof(ProbeSummary))]
    private double? uncachedMilliseconds;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(AverageMilliseconds))]
    [NotifyPropertyChangedFor(nameof(DotComDisplay))]
    [NotifyPropertyChangedFor(nameof(AverageDisplay))]
    [NotifyPropertyChangedFor(nameof(ProbeSummary))]
    private double? dotComMilliseconds;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ProbeStandardDeviationDisplay))]
    [NotifyPropertyChangedFor(nameof(ProbeStandardDeviationSummary))]
    [NotifyPropertyChangedFor(nameof(MeanProbeStandardDeviationMilliseconds))]
    [NotifyPropertyChangedFor(nameof(ProbeSummary))]
    private double? cachedStandardDeviationMilliseconds;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ProbeStandardDeviationDisplay))]
    [NotifyPropertyChangedFor(nameof(ProbeStandardDeviationSummary))]
    [NotifyPropertyChangedFor(nameof(MeanProbeStandardDeviationMilliseconds))]
    [NotifyPropertyChangedFor(nameof(ProbeSummary))]
    private double? uncachedStandardDeviationMilliseconds;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ProbeStandardDeviationDisplay))]
    [NotifyPropertyChangedFor(nameof(ProbeStandardDeviationSummary))]
    [NotifyPropertyChangedFor(nameof(MeanProbeStandardDeviationMilliseconds))]
    [NotifyPropertyChangedFor(nameof(ProbeSummary))]
    private double? dotComStandardDeviationMilliseconds;

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
    [NotifyPropertyChangedFor(nameof(SidelinedSummary))]
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

    public string CachedDisplay => UiValueFormatter.FormatMilliseconds(CachedMilliseconds);

    public string UncachedDisplay => UiValueFormatter.FormatMilliseconds(UncachedMilliseconds);

    public string DotComDisplay => UiValueFormatter.FormatMilliseconds(DotComMilliseconds);

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

    public string AverageDisplay => UiValueFormatter.FormatMilliseconds(AverageMilliseconds);

    public double? MeanProbeStandardDeviationMilliseconds
    {
        get
        {
            List<double> values = [];

            if (CachedStandardDeviationMilliseconds is double cached)
            {
                values.Add(cached);
            }

            if (UncachedStandardDeviationMilliseconds is double uncached)
            {
                values.Add(uncached);
            }

            if (DotComStandardDeviationMilliseconds is double dotCom)
            {
                values.Add(dotCom);
            }

            return values.Count == 0 ? null : values.Average();
        }
    }

    public string ProbeStandardDeviationDisplay => UiValueFormatter.FormatProbeTriplet(
        CachedStandardDeviationMilliseconds,
        UncachedStandardDeviationMilliseconds,
        DotComStandardDeviationMilliseconds,
        nullPlaceholder: "<2",
        allNullText: "insufficient");

    public string ProbeStandardDeviationSummary =>
        $"Std dev over successful repeated attempts for Cached / Uncached / DotCom: {UiValueFormatter.FormatProbeTriplet(CachedStandardDeviationMilliseconds, UncachedStandardDeviationMilliseconds, DotComStandardDeviationMilliseconds, includeUnit: true, nullPlaceholder: "<2", allNullText: "insufficient samples")}. <2 means fewer than 2 successful samples for that probe.";

    public string ProbeSummary =>
        $"Cached: {CachedDisplay} | Uncached: {UncachedDisplay} | DotCom: {DotComDisplay} | Avg: {AverageDisplay} | StdDev (C/U/D): {UiValueFormatter.FormatProbeTriplet(CachedStandardDeviationMilliseconds, UncachedStandardDeviationMilliseconds, DotComStandardDeviationMilliseconds, includeUnit: true, nullPlaceholder: "<2", allNullText: "insufficient samples")} | Poisoning: {UiValueFormatter.FormatPercent(PoisoningConfidence)}"
        + (string.IsNullOrWhiteSpace(PoisoningEvidence) ? string.Empty : $" | {PoisoningEvidence}");

    public string SidelinedSummary => IsSidelined
        ? "Excluded from future benchmark runs until restored."
        : "Included in future benchmark runs.";

    public void ApplyBenchmarkResult(DnsBenchmarkResult result)
    {
        CachedMilliseconds = result.CachedMilliseconds;
        UncachedMilliseconds = result.UncachedMilliseconds;
        DotComMilliseconds = result.DotComMilliseconds;
        CachedStandardDeviationMilliseconds = result.CachedStandardDeviationMilliseconds;
        UncachedStandardDeviationMilliseconds = result.UncachedStandardDeviationMilliseconds;
        DotComStandardDeviationMilliseconds = result.DotComStandardDeviationMilliseconds;
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
            CachedStandardDeviationMilliseconds = CachedStandardDeviationMilliseconds,
            UncachedStandardDeviationMilliseconds = UncachedStandardDeviationMilliseconds,
            DotComStandardDeviationMilliseconds = DotComStandardDeviationMilliseconds,
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
        SidelinedChanged?.Invoke(this);
    }

    public bool MatchesFilter(string normalizedTerm)
    {
        if (string.IsNullOrWhiteSpace(normalizedTerm))
        {
            return true;
        }

        return SearchKey.Contains(normalizedTerm, System.StringComparison.Ordinal);
    }
}

