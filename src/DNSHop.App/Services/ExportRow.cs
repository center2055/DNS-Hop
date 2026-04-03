using DNSHop.App.Models;

namespace DNSHop.App.Services;

internal sealed record ExportRow(
    string Endpoint,
    string Provider,
    string Protocol,
    string Status,
    bool SupportsDnssec,
    bool RedirectsNxDomain,
    double PoisoningConfidence,
    string? PoisoningEvidence,
    double? CachedMs,
    double? UncachedMs,
    double? DotComMs,
    double? AverageMs,
    double? CachedStdDevMs,
    double? UncachedStdDevMs,
    double? DotComStdDevMs,
    double? MeanProbeStdDevMs,
    int SuccessfulQueries,
    int FailedQueries,
    string? LastError)
{
    public static ExportRow FromResult(DnsBenchmarkResult result)
    {
        return new ExportRow(
            result.Server.EndpointDisplay,
            result.Server.Provider,
            result.Server.Protocol.ToString(),
            result.Status.ToString(),
            result.SupportsDnssec,
            result.RedirectsNxDomain,
            result.PoisoningConfidence,
            result.PoisoningEvidence,
            result.CachedMilliseconds,
            result.UncachedMilliseconds,
            result.DotComMilliseconds,
            result.AverageMilliseconds,
            result.CachedStandardDeviationMilliseconds,
            result.UncachedStandardDeviationMilliseconds,
            result.DotComStandardDeviationMilliseconds,
            result.MeanProbeStandardDeviationMilliseconds,
            result.SuccessfulQueries,
            result.FailedQueries,
            result.LastError);
    }
}
