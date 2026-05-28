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
    // Compares the resolver IPs the user applied via DNS Hop against the resolver IP
    // Windows / Linux is actually using right now. No external network call is needed
    // — relying on whoami.cloudflare only worked when the system DNS was already a
    // Cloudflare resolver, which made the test useless for anything else.
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
                Passed = false,
                CheckedAt = DateTimeOffset.UtcNow,
                ExpectedResolver = expectedIps.FirstOrDefault(),
                ObservedResolver = null,
                Note = "Could not detect the active system resolver.",
            });
        }

        if (expectedIps.Count == 0)
        {
            return Task.FromResult(new LeakTestResult
            {
                Passed = false,
                CheckedAt = DateTimeOffset.UtcNow,
                ObservedResolver = observed,
                Note = "Apply a DNS profile or resolver first — there is nothing to compare against yet.",
            });
        }

        foreach (var expected in expectedIps.Where(static s => !string.IsNullOrWhiteSpace(s)))
        {
            if (string.Equals(expected, observed, StringComparison.OrdinalIgnoreCase)
                || ShareSubnet(observed, expected))
            {
                return Task.FromResult(new LeakTestResult
                {
                    Passed = true,
                    CheckedAt = DateTimeOffset.UtcNow,
                    ExpectedResolver = expected,
                    ObservedResolver = observed,
                });
            }
        }

        return Task.FromResult(new LeakTestResult
        {
            Passed = false,
            CheckedAt = DateTimeOffset.UtcNow,
            ExpectedResolver = expectedIps.FirstOrDefault(),
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
