using DNSHop.App.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace DNSHop.App.Services;

public sealed class RecommendationService
{
    public string BuildConclusion(IReadOnlyList<DnsBenchmarkResult> results)
    {
        if (results.Count == 0)
        {
            return "Run a benchmark to generate recommendations.";
        }

        var eligible = results
            .Where(result => result.Status == DnsServerStatus.Alive)
            .Where(result => !result.RedirectsNxDomain)
            .Where(result => result.AverageMilliseconds is not null)
            .OrderBy(result => result.AverageMilliseconds ?? double.MaxValue)
            .ToArray();

        if (eligible.Length == 0)
        {
            return "No fully eligible resolvers were found with complete probe data. Check connectivity/timeouts and remove redirecting/dead endpoints.";
        }

        var primary = eligible[0];

        // Pick a secondary from a DIFFERENT provider for resilience. If every eligible
        // resolver belongs to the same provider, fall back to the second fastest overall.
        var secondary = eligible.Skip(1)
            .FirstOrDefault(r => !string.Equals(r.Server.Provider, primary.Server.Provider, StringComparison.OrdinalIgnoreCase));
        secondary ??= eligible.Length > 1 ? eligible[1] : null;

        var deadCount = results.Count(result => result.Status == DnsServerStatus.Dead);
        var redirectCount = results.Count(result => result.Status == DnsServerStatus.Redirecting);
        var dnssecCount = results.Count(result => result.SupportsDnssec);

        var builder = new StringBuilder();
        builder.AppendLine("Primary Recommendation");
        builder.AppendLine($"- {primary.Server.EndpointDisplay} ({primary.Server.Provider})");
        builder.AppendLine($"- Average latency: {FormatMs(primary.AverageMilliseconds)}");
        builder.AppendLine($"- DNSSEC: {(primary.SupportsDnssec ? "Yes" : "No")}");
        builder.AppendLine($"- Cached: {FormatMs(primary.CachedMilliseconds)}, Uncached: {FormatMs(primary.UncachedMilliseconds)}, DotCom: {FormatMs(primary.DotComMilliseconds)}");

        if (secondary is not null)
        {
            builder.AppendLine();
            builder.AppendLine("Secondary Recommendation");
            builder.AppendLine($"- {secondary.Server.EndpointDisplay} ({secondary.Server.Provider})");
            builder.AppendLine($"- Average latency: {FormatMs(secondary.AverageMilliseconds)}");
            builder.AppendLine($"- DNSSEC: {(secondary.SupportsDnssec ? "Yes" : "No")}");

            if (string.Equals(primary.Server.Provider, secondary.Server.Provider, StringComparison.OrdinalIgnoreCase))
            {
                builder.AppendLine($"- Note: Both recommendations are from {primary.Server.Provider}. Consider adding a resolver from a different provider for redundancy.");
            }
        }

        builder.AppendLine();
        builder.AppendLine("Observations");
        builder.AppendLine($"- Alive servers: {results.Count - deadCount}/{results.Count}");
        builder.AppendLine($"- Redirecting servers: {redirectCount}");
        builder.AppendLine($"- DNSSEC-validating servers: {dnssecCount}");

        builder.AppendLine();
        builder.AppendLine("Suggested policy");
        builder.AppendLine("- Use the primary endpoint as preferred DNS and the secondary endpoint as fallback.");
        builder.AppendLine("- Keep redirecting and dead servers sidelined to avoid user-visible failures.");
        if (dnssecCount > 0)
        {
            builder.AppendLine("- Prefer DNSSEC-validating resolvers for protection against DNS spoofing.");
        }

        return builder.ToString().TrimEnd();
    }

    private static string FormatMs(double? value)
    {
        return value is null ? "n/a" : $"{value:0.0} ms";
    }
}
