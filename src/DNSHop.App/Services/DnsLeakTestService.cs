using DNSHop.App.Models;
using DnsClient;
using System;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace DNSHop.App.Services;

internal sealed class DnsLeakTestService
{
    public async Task<LeakTestResult> RunAsync(string? expectedResolver, CancellationToken cancellationToken = default)
    {
        try
        {
            var options = new LookupClientOptions
            {
                Timeout = TimeSpan.FromSeconds(3),
                UseCache = false,
                Retries = 1,
            };

            var client = new LookupClient(options);
            // whoami.cloudflare returns a TXT record echoing the public resolver address.
            var result = await client.QueryAsync("whoami.cloudflare", QueryType.TXT, cancellationToken: cancellationToken).ConfigureAwait(false);

            string? observed = result.Answers
                .TxtRecords()
                .SelectMany(r => r.Text)
                .Select(t => t.Trim())
                .FirstOrDefault(t => IPAddress.TryParse(t, out _));

            if (string.IsNullOrWhiteSpace(observed))
            {
                return new LeakTestResult
                {
                    Passed = false,
                    CheckedAt = DateTimeOffset.UtcNow,
                    ExpectedResolver = expectedResolver,
                    ObservedResolver = null,
                    Note = "No echo answer from whoami.cloudflare",
                };
            }

            bool match = string.IsNullOrWhiteSpace(expectedResolver)
                || string.Equals(observed, expectedResolver, StringComparison.OrdinalIgnoreCase)
                || ShareSubnet(observed, expectedResolver);

            return new LeakTestResult
            {
                Passed = match,
                CheckedAt = DateTimeOffset.UtcNow,
                ExpectedResolver = expectedResolver,
                ObservedResolver = observed,
            };
        }
        catch (Exception ex)
        {
            return new LeakTestResult
            {
                Passed = false,
                CheckedAt = DateTimeOffset.UtcNow,
                ExpectedResolver = expectedResolver,
                Note = ex.Message,
            };
        }
    }

    private static bool ShareSubnet(string observed, string? expected)
    {
        if (string.IsNullOrWhiteSpace(expected))
        {
            return false;
        }

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
