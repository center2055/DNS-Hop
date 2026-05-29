using DNSHop.App.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace DNSHop.App.Services;

internal sealed class DnsLeakTestService
{
    // Compares the resolver IPs the user applied via DNS Hop against the resolver the
    // system is actually using right now. Three real outcomes plus an "undetectable"
    // guard — crucially, "the user never applied anything in-app" is NOT a leak, it
    // just means there is nothing to verify against.
    public Task<LeakTestResult> RunAsync(
        IReadOnlyList<string> expectedIps,
        string? detectedResolverAddress,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var observed = (detectedResolverAddress ?? string.Empty).Trim();
        if (observed.Length == 0
            || string.Equals(observed, "Unknown", StringComparison.OrdinalIgnoreCase))
        {
            return Task.FromResult(new LeakTestResult
            {
                Outcome = LeakTestOutcome.Undetectable,
                CheckedAt = DateTimeOffset.UtcNow,
                ExpectedResolver = expectedIps.FirstOrDefault(),
                ObservedResolver = null,
                Note = "Could not detect the active system resolver.",
            });
        }

        var applied = expectedIps
            .Where(static s => !string.IsNullOrWhiteSpace(s))
            .ToArray();

        if (applied.Length == 0)
        {
            // Nothing was applied through DNS Hop (e.g. DNS set on the router or in
            // Windows directly). There is no in-app target, so this is informational,
            // not a leak.
            return Task.FromResult(new LeakTestResult
            {
                Outcome = LeakTestOutcome.NotApplicable,
                CheckedAt = DateTimeOffset.UtcNow,
                ObservedResolver = observed,
                Note = "No resolver was applied through DNS Hop, so there is nothing to compare against.",
            });
        }

        foreach (var expected in applied)
        {
            if (string.Equals(expected, observed, StringComparison.OrdinalIgnoreCase)
                || ShareSubnet(observed, expected))
            {
                return Task.FromResult(new LeakTestResult
                {
                    Outcome = LeakTestOutcome.Clear,
                    CheckedAt = DateTimeOffset.UtcNow,
                    ExpectedResolver = expected,
                    ObservedResolver = observed,
                });
            }
        }

        return Task.FromResult(new LeakTestResult
        {
            Outcome = LeakTestOutcome.Override,
            CheckedAt = DateTimeOffset.UtcNow,
            ExpectedResolver = applied[0],
            ObservedResolver = observed,
            Note = $"System resolver {observed} is not in the applied set.",
        });
    }

    private static bool ShareSubnet(string observed, string expected)
    {
        if (!IPAddress.TryParse(observed, out var observedIp)
            || !IPAddress.TryParse(expected, out var expectedIp))
        {
            return false;
        }

        var a = observedIp.GetAddressBytes();
        var b = expectedIp.GetAddressBytes();
        if (a.Length != b.Length || a.Length < 3)
        {
            return false;
        }

        // /24 for IPv4, /48 for IPv6 — close enough for anycast PoPs of the same provider.
        int prefix = a.Length == 4 ? 3 : 6;
        for (int i = 0; i < prefix; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }

        return true;
    }
}
