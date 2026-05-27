using System;
using System.Globalization;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DNSHop.App.Services;

internal sealed class GeoLocationService
{
    private string? _cachedRegion;
    private DateTimeOffset _cachedAt;

    public string Region => _cachedRegion ?? GuessFromCulture();

    public async Task<string> DetectAsync(CancellationToken cancellationToken = default)
    {
        if (_cachedRegion is not null && DateTimeOffset.UtcNow - _cachedAt < TimeSpan.FromHours(6))
        {
            return _cachedRegion;
        }

        var fromCulture = GuessFromCulture();
        _cachedRegion = fromCulture;
        _cachedAt = DateTimeOffset.UtcNow;

        try
        {
            using var http = new HttpClient
            {
                Timeout = TimeSpan.FromSeconds(4),
            };
            http.DefaultRequestHeaders.UserAgent.ParseAdd("DNS-Hop/2.0");

            // Country-only lookup via Cloudflare trace; no precise location.
            using var response = await http.GetAsync("https://www.cloudflare.com/cdn-cgi/trace", cancellationToken).ConfigureAwait(false);
            if (response.IsSuccessStatusCode)
            {
                string body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
                string? country = ParseCountry(body);
                if (!string.IsNullOrWhiteSpace(country))
                {
                    _cachedRegion = country;
                }
            }
        }
        catch (Exception ex)
        {
            AppDiagnostics.WriteWarning("Geo", $"Region detection failed: {ex.Message}");
        }

        return _cachedRegion ?? fromCulture;
    }

    private static string GuessFromCulture()
    {
        try
        {
            var ri = new RegionInfo(CultureInfo.CurrentCulture.Name);
            return ri.TwoLetterISORegionName.ToUpperInvariant();
        }
        catch (Exception)
        {
            return "US";
        }
    }

    private static string? ParseCountry(string traceBody)
    {
        foreach (var line in traceBody.Split('\n'))
        {
            int eq = line.IndexOf('=');
            if (eq <= 0)
            {
                continue;
            }

            if (line.AsSpan(0, eq).Equals("loc".AsSpan(), StringComparison.OrdinalIgnoreCase))
            {
                return line.Substring(eq + 1).Trim().ToUpperInvariant();
            }
        }

        return null;
    }
}
