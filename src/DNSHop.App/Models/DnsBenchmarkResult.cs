using System.Collections.Generic;
using System.Linq;

namespace DNSHop.App.Models;

public sealed class DnsBenchmarkResult
{
    public required DnsServerDefinition Server { get; init; }

    public double? CachedMilliseconds { get; init; }

    public double? UncachedMilliseconds { get; init; }

    public double? DotComMilliseconds { get; init; }

    public DnsServerStatus Status { get; init; }

    public bool SupportsDnssec { get; init; }

    public bool RedirectsNxDomain { get; init; }

    public double PoisoningConfidence { get; init; }

    public string? PoisoningEvidence { get; init; }

    public int SuccessfulQueries { get; init; }

    public int FailedQueries { get; init; }

    public string? LastError { get; init; }

    public double? AverageMilliseconds
    {
        get
        {
            // Keep exports/recommendations consistent with the UI:
            // no average is reported when any of the three core probes failed.
            if (CachedMilliseconds is null || UncachedMilliseconds is null || DotComMilliseconds is null)
            {
                return null;
            }

            List<double> values = [CachedMilliseconds.Value, UncachedMilliseconds.Value, DotComMilliseconds.Value];
            return values.Average();
        }
    }
}

