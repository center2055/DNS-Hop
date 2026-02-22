using DNSHop.App.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace DNSHop.App.Services;

public sealed partial class DnsServerListService
{
    private static readonly Uri PublicResolverFeed = new("https://public-dns.info/nameservers-all.json");
    private static readonly TimeSpan RemoteFeedTimeout = TimeSpan.FromSeconds(4);
    private const int MaxNormalizedServers = 260;
    private const int MaxRemoteFeedServers = 18;
    private const int CancellationCheckInterval = 64;

    private static readonly HttpClient HttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(6),
    };

    private readonly SemaphoreSlim _localLoadGate = new(1, 1);
    private IReadOnlyList<DnsServerDefinition>? _cachedLocalServers;
    private string? _cachedResolverIniFingerprint;

    public async Task<IReadOnlyList<DnsServerDefinition>> GetLocalServersAsync(CancellationToken cancellationToken)
    {
        string currentFingerprint = GetResolverIniFingerprint();
        if (TryGetCachedLocalServers(currentFingerprint, out var cached))
        {
            return cached;
        }

        await _localLoadGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (TryGetCachedLocalServers(currentFingerprint, out cached))
            {
                return cached;
            }

            var normalized = await Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();

                var servers = GetBuiltInServers().ToList();
                var existingKeys = new HashSet<string>(
                    servers.Select(static server => BuildServerKey(server)),
                    StringComparer.OrdinalIgnoreCase);

                servers.AddRange(LoadIniResolversFromFile(existingKeys, MaxNormalizedServers, cancellationToken));
                return NormalizeServerList(servers);
            }, cancellationToken).ConfigureAwait(false);

            _cachedLocalServers = normalized;
            _cachedResolverIniFingerprint = currentFingerprint;
            return normalized;
        }
        finally
        {
            _localLoadGate.Release();
        }
    }

    public async Task<IReadOnlyList<DnsServerDefinition>> GetRemoteServersAsync(CancellationToken cancellationToken)
    {
        return await FetchPublicResolverFeedAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<DnsServerDefinition>> GetServersAsync(bool includeRemoteList, CancellationToken cancellationToken)
    {
        var servers = (await GetLocalServersAsync(cancellationToken).ConfigureAwait(false)).ToList();

        if (includeRemoteList)
        {
            try
            {
                using var remoteTimeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                remoteTimeoutCts.CancelAfter(RemoteFeedTimeout);
                var remoteServers = await FetchPublicResolverFeedAsync(remoteTimeoutCts.Token).ConfigureAwait(false);
                servers.AddRange(remoteServers);
            }
            catch
            {
                // Startup must remain reliable even if external feed is unavailable.
            }
        }

        return NormalizeServerList(servers);
    }

    private static IReadOnlyList<DnsServerDefinition> NormalizeServerList(IEnumerable<DnsServerDefinition> servers)
    {
        return servers
            .Where(static server => !string.IsNullOrWhiteSpace(server.AddressOrHost))
            .GroupBy(static server => BuildServerKey(server), StringComparer.OrdinalIgnoreCase)
            .Select(static group => group.First())
            .Take(MaxNormalizedServers)
            .ToArray();
    }

    private static IEnumerable<DnsServerDefinition> GetBuiltInServers()
    {
        return
        [
            // --- Major global providers (UDP/TCP) ---
            DnsServerDefinition.CreateUdpTcp("1.1.1.1", "Cloudflare"),
            DnsServerDefinition.CreateUdpTcp("1.0.0.1", "Cloudflare"),
            DnsServerDefinition.CreateUdpTcp("8.8.8.8", "Google"),
            DnsServerDefinition.CreateUdpTcp("8.8.4.4", "Google"),
            DnsServerDefinition.CreateUdpTcp("9.9.9.9", "Quad9"),
            DnsServerDefinition.CreateUdpTcp("149.112.112.112", "Quad9"),
            DnsServerDefinition.CreateUdpTcp("208.67.222.222", "OpenDNS"),
            DnsServerDefinition.CreateUdpTcp("208.67.220.220", "OpenDNS"),
            DnsServerDefinition.CreateUdpTcp("76.76.2.0", "ControlD"),
            DnsServerDefinition.CreateUdpTcp("95.85.95.85", "Gcore"),
            DnsServerDefinition.CreateUdpTcp("2.56.220.2", "Gcore"),
            DnsServerDefinition.CreateUdpTcp("194.169.169.169", "Surfshark"),
            // Cox public resolver pair (ISP-assigned in many regions).
            DnsServerDefinition.CreateUdpTcp("68.105.28.16", "Cox"),
            DnsServerDefinition.CreateUdpTcp("68.105.29.16", "Cox"),
            DnsServerDefinition.CreateUdpTcp("216.146.35.35", "Dyn (Oracle)"),
            DnsServerDefinition.CreateUdpTcp("216.146.36.36", "Dyn (Oracle)"),
            DnsServerDefinition.CreateUdpTcp("64.6.64.6", "UltraDNS"),
            DnsServerDefinition.CreateUdpTcp("64.6.65.6", "UltraDNS"),
            DnsServerDefinition.CreateUdpTcp("46.227.200.54", "FAELIX"),
            DnsServerDefinition.CreateUdpTcp("46.227.200.55", "FAELIX"),
            DnsServerDefinition.CreateUdpTcp("2a01:9e00::54", "FAELIX"),
            DnsServerDefinition.CreateUdpTcp("2a01:9e00::55", "FAELIX"),
            DnsServerDefinition.CreateUdpTcp("185.222.222.222", "DNS.SB"),
            DnsServerDefinition.CreateUdpTcp("45.11.45.11", "DNS.SB"),
            DnsServerDefinition.CreateUdpTcp("2a09::", "DNS.SB"),
            DnsServerDefinition.CreateUdpTcp("2a11::", "DNS.SB"),

            // --- Providers from publicdns.xyz ---
            DnsServerDefinition.CreateUdpTcp("209.244.0.3", "Level3"),
            DnsServerDefinition.CreateUdpTcp("209.244.0.4", "Level3"),
            DnsServerDefinition.CreateUdpTcp("64.6.64.6", "UltraDNS"),
            DnsServerDefinition.CreateUdpTcp("64.6.65.6", "UltraDNS"),
            DnsServerDefinition.CreateUdpTcp("8.26.56.26", "Comodo Secure"),
            DnsServerDefinition.CreateUdpTcp("8.20.247.20", "Comodo Secure"),
            DnsServerDefinition.CreateUdpTcp("84.200.69.80", "DNS.WATCH"),
            DnsServerDefinition.CreateUdpTcp("84.200.70.40", "DNS.WATCH"),
            DnsServerDefinition.CreateUdpTcp("199.85.126.10", "Norton ConnectSafe"),
            DnsServerDefinition.CreateUdpTcp("199.85.127.10", "Norton ConnectSafe"),
            DnsServerDefinition.CreateUdpTcp("81.218.119.11", "GreenTeamDNS"),
            DnsServerDefinition.CreateUdpTcp("209.88.198.133", "GreenTeamDNS"),
            DnsServerDefinition.CreateUdpTcp("195.46.39.39", "SafeDNS"),
            DnsServerDefinition.CreateUdpTcp("195.46.39.40", "SafeDNS"),
            DnsServerDefinition.CreateUdpTcp("185.121.177.177", "OpenNIC"),
            DnsServerDefinition.CreateUdpTcp("169.239.202.202", "OpenNIC"),
            DnsServerDefinition.CreateUdpTcp("208.76.50.50", "SmartViper"),
            DnsServerDefinition.CreateUdpTcp("208.76.51.51", "SmartViper"),
            DnsServerDefinition.CreateUdpTcp("80.80.80.80", "Freenom World"),
            DnsServerDefinition.CreateUdpTcp("80.80.81.81", "Freenom World"),
            DnsServerDefinition.CreateUdpTcp("216.146.35.35", "Dyn"),
            DnsServerDefinition.CreateUdpTcp("216.146.36.36", "Dyn"),
            DnsServerDefinition.CreateUdpTcp("37.235.1.174", "FreeDNS"),
            DnsServerDefinition.CreateUdpTcp("37.235.1.177", "FreeDNS"),
            DnsServerDefinition.CreateUdpTcp("198.101.242.72", "Alternate DNS"),
            DnsServerDefinition.CreateUdpTcp("23.253.163.53", "Alternate DNS"),
            DnsServerDefinition.CreateUdpTcp("77.88.8.8", "Yandex.DNS"),
            DnsServerDefinition.CreateUdpTcp("77.88.8.1", "Yandex.DNS"),
            DnsServerDefinition.CreateUdpTcp("91.239.100.100", "UncensoredDNS"),
            DnsServerDefinition.CreateUdpTcp("89.233.43.71", "UncensoredDNS"),
            DnsServerDefinition.CreateUdpTcp("74.82.42.42", "Hurricane Electric"),
            DnsServerDefinition.CreateUdpTcp("109.69.8.51", "puntCAT"),
            DnsServerDefinition.CreateUdpTcp("156.154.70.1", "UltraDNS"),
            DnsServerDefinition.CreateUdpTcp("156.154.71.1", "UltraDNS"),
            DnsServerDefinition.CreateUdpTcp("1.2.4.8", "CNNIC SDNS"),
            DnsServerDefinition.CreateUdpTcp("210.2.4.8", "CNNIC SDNS"),
            DnsServerDefinition.CreateUdpTcp("223.5.5.5", "AliDNS"),
            DnsServerDefinition.CreateUdpTcp("223.6.6.6", "AliDNS"),
            DnsServerDefinition.CreateUdpTcp("180.76.76.76", "Baidu"),
            DnsServerDefinition.CreateUdpTcp("119.29.29.29", "DNSPod"),
            DnsServerDefinition.CreateUdpTcp("119.28.28.28", "DNSPod"),
            DnsServerDefinition.CreateUdpTcp("114.114.114.114", "114DNS"),
            DnsServerDefinition.CreateUdpTcp("114.114.115.115", "114DNS"),
            DnsServerDefinition.CreateUdpTcp("117.50.11.11", "OneDNS"),
            DnsServerDefinition.CreateUdpTcp("117.50.22.22", "OneDNS"),
            DnsServerDefinition.CreateUdpTcp("101.226.4.6", "DNSpai"),
            DnsServerDefinition.CreateUdpTcp("218.30.118.6", "DNSpai"),

            // --- IPv6 (major providers) ---
            DnsServerDefinition.CreateUdpTcp("2606:4700:4700::1111", "Cloudflare"),
            DnsServerDefinition.CreateUdpTcp("2606:4700:4700::1001", "Cloudflare"),
            DnsServerDefinition.CreateUdpTcp("2001:4860:4860::8888", "Google"),
            DnsServerDefinition.CreateUdpTcp("2001:4860:4860::8844", "Google"),
            DnsServerDefinition.CreateUdpTcp("2620:fe::fe", "Quad9"),
            DnsServerDefinition.CreateUdpTcp("2620:fe::9", "Quad9"),
            DnsServerDefinition.CreateUdpTcp("2620:0:ccc::2", "OpenDNS"),
            DnsServerDefinition.CreateUdpTcp("2620:0:ccd::2", "OpenDNS"),
            DnsServerDefinition.CreateUdpTcp("2001:578:3f::10", "Cox"),
            DnsServerDefinition.CreateUdpTcp("2001:578:3f:1::10", "Cox"),
            DnsServerDefinition.CreateUdpTcp("2404:1a8:7f01:a::3", "IIJ"),
            DnsServerDefinition.CreateUdpTcp("2a12:dd47:1030::", "Applied Privacy"),

            // --- DoH endpoints ---
            DnsServerDefinition.CreateDoh("https://cloudflare-dns.com/dns-query", "Cloudflare"),
            DnsServerDefinition.CreateDoh("https://dns.google/dns-query", "Google"),
            DnsServerDefinition.CreateDoh("https://dns.quad9.net/dns-query", "Quad9"),
            DnsServerDefinition.CreateDoh("https://dns.adguard-dns.com/dns-query", "AdGuard"),
            DnsServerDefinition.CreateDoh("https://doh.opendns.com/dns-query", "OpenDNS"),
            DnsServerDefinition.CreateDoh("https://dns.surfsharkdns.com/dns-query", "Surfshark"),
            DnsServerDefinition.CreateDoh("https://dns.mullvad.net/dns-query", "Mullvad"),
            DnsServerDefinition.CreateDoh("https://adblock.dns.mullvad.net/dns-query", "Mullvad"),
            DnsServerDefinition.CreateDoh("https://rdns.faelix.net/", "FAELIX"),
            DnsServerDefinition.CreateDoh("https://pdns.faelix.net/", "FAELIX"),
            DnsServerDefinition.CreateDoh("https://dns.digitale-gesellschaft.ch/dns-query", "Digitale Gesellschaft"),
            DnsServerDefinition.CreateDoh("https://doh.applied-privacy.net/query", "Applied Privacy"),
            DnsServerDefinition.CreateDoh("https://doh.dns.sb/dns-query", "DNS.SB"),
            DnsServerDefinition.CreateDoh("https://public.dns.iij.jp/dns-query", "IIJ"),
            DnsServerDefinition.CreateDoh("https://dns.snopyta.org/", "Snopyta"),

            // --- DoT endpoints ---
            DnsServerDefinition.CreateDot("1.1.1.1", "cloudflare-dns.com", "Cloudflare"),
            DnsServerDefinition.CreateDot("8.8.8.8", "dns.google", "Google"),
            DnsServerDefinition.CreateDot("9.9.9.9", "dns.quad9.net", "Quad9"),
            DnsServerDefinition.CreateDot("94.140.14.14", "dns.adguard-dns.com", "AdGuard"),
            DnsServerDefinition.CreateDot("194.169.169.169", "dns.surfsharkdns.com", "Surfshark"),
            DnsServerDefinition.CreateDot("194.242.2.2", "dns.mullvad.net", "Mullvad"),
            DnsServerDefinition.CreateDot("194.242.2.3", "adblock.dns.mullvad.net", "Mullvad"),
            DnsServerDefinition.CreateDot("46.227.200.54", "rdns.faelix.net", "FAELIX"),
            DnsServerDefinition.CreateDot("46.227.200.55", "rdns.faelix.net", "FAELIX"),
            DnsServerDefinition.CreateDot("46.227.200.54", "pdns.faelix.net", "FAELIX"),
            DnsServerDefinition.CreateDot("46.227.200.55", "pdns.faelix.net", "FAELIX"),
            DnsServerDefinition.CreateDot("dns.digitale-gesellschaft.ch", "dns.digitale-gesellschaft.ch", "Digitale Gesellschaft"),
            DnsServerDefinition.CreateDot("146.255.56.98", "dot1.applied-privacy.net", "Applied Privacy"),
            DnsServerDefinition.CreateDot("185.222.222.222", "dot.sb", "DNS.SB"),
            DnsServerDefinition.CreateDot("45.11.45.11", "dot.sb", "DNS.SB"),
            DnsServerDefinition.CreateDot("public.dns.iij.jp", "public.dns.iij.jp", "IIJ"),
        ];
    }

    private static async Task<IReadOnlyList<DnsServerDefinition>> FetchPublicResolverFeedAsync(CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await HttpClient
            .GetAsync(PublicResolverFeed, cancellationToken)
            .ConfigureAwait(false);

        response.EnsureSuccessStatusCode();

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);

        var entries = await JsonSerializer
            .DeserializeAsync(stream, DnsServerListJsonContext.Default.PublicDnsEntryArray, cancellationToken)
            .ConfigureAwait(false)
            ?? [];

        var topServers = entries
            .Where(entry => !string.IsNullOrWhiteSpace(entry.Ip))
            .Where(entry => (entry.Reliability ?? 0) >= 0.95)
            .Where(entry => IPAddress.TryParse(entry.Ip, out _))
            .OrderByDescending(entry => entry.Reliability ?? 0)
            .ToArray();

        var servers = new List<DnsServerDefinition>(capacity: Math.Min(MaxRemoteFeedServers, topServers.Length));

        foreach (var entry in topServers.Take(MaxRemoteFeedServers))
        {
            cancellationToken.ThrowIfCancellationRequested();
            // Keep startup responsive: avoid reverse lookups here.
            string provider = DetectProvider(entry.Ip!, entry.Name);
            servers.Add(DnsServerDefinition.CreateUdpTcp(entry.Ip!, provider));
        }

        return servers;
    }

    private static IReadOnlyList<DnsServerDefinition> LoadIniResolversFromFile(
        HashSet<string> existingKeys,
        int maxUniqueTotal,
        CancellationToken cancellationToken)
    {
        string? path = FindResolverIniPath();
        if (path is null)
        {
            return [];
        }

        var servers = new List<DnsServerDefinition>();
        int scanned = 0;

        foreach (string rawLine in File.ReadLines(path))
        {
            if ((scanned++ % CancellationCheckInterval) == 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
            }

            if (existingKeys.Count >= maxUniqueTotal)
            {
                break;
            }

            string line = rawLine.Trim();

            if (line.Length == 0 || line.StartsWith('#') || line.StartsWith(';'))
            {
                continue;
            }

            string[] parts = line.Split((char[]?)null, 2, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (parts.Length == 0)
            {
                continue;
            }

            string ipAddress = parts[0];
            if (!IPAddress.TryParse(ipAddress, out _))
            {
                continue;
            }

            string hostName = parts.Length > 1 ? parts[1].Trim() : string.Empty;
            if (hostName.Contains("no official", StringComparison.OrdinalIgnoreCase) || hostName.Contains('·'))
            {
                hostName = string.Empty;
            }

            string provider = DetectProvider(ipAddress, hostName);
            var server = DnsServerDefinition.CreateUdpTcp(ipAddress, provider);
            if (!existingKeys.Add(BuildServerKey(server)))
            {
                continue;
            }

            servers.Add(server);
        }

        return servers;
    }

    private bool TryGetCachedLocalServers(
        string currentFingerprint,
        out IReadOnlyList<DnsServerDefinition> cachedServers)
    {
        if (_cachedLocalServers is not null
            && string.Equals(_cachedResolverIniFingerprint, currentFingerprint, StringComparison.Ordinal))
        {
            cachedServers = _cachedLocalServers;
            return true;
        }

        cachedServers = [];
        return false;
    }

    private static string BuildServerKey(DnsServerDefinition server)
        => $"{server.Protocol}|{server.EndpointDisplay}";

    private static string GetResolverIniFingerprint()
    {
        string? path = FindResolverIniPath();
        if (path is null)
        {
            return "<no-ini>";
        }

        try
        {
            var fileInfo = new FileInfo(path);
            return $"{fileInfo.FullName}|{fileInfo.Length}|{fileInfo.LastWriteTimeUtc.Ticks}";
        }
        catch
        {
            return path;
        }
    }

    private static string? FindResolverIniPath()
    {
        const string iniFileName = "New Public DNS Resolvers.ini";
        string[] candidatePaths =
        [
            Path.Combine(AppContext.BaseDirectory, iniFileName),
            Path.Combine(Environment.CurrentDirectory, iniFileName),
            Path.Combine(AppContext.BaseDirectory, "Assets", iniFileName),
        ];

        return candidatePaths.FirstOrDefault(File.Exists);
    }

    private static string DetectProvider(string ipAddress, string? hostName = null)
    {
        if (!string.IsNullOrWhiteSpace(hostName))
        {
            string host = hostName.Trim();

            if (host.Contains("cloudflare", StringComparison.OrdinalIgnoreCase))
            {
                return "Cloudflare";
            }

            if (host.Contains("google", StringComparison.OrdinalIgnoreCase))
            {
                return "Google";
            }

            if (host.Contains("quad9", StringComparison.OrdinalIgnoreCase))
            {
                return "Quad9";
            }

            if (host.Contains("opendns", StringComparison.OrdinalIgnoreCase))
            {
                return "OpenDNS";
            }

            if (host.Contains("controld", StringComparison.OrdinalIgnoreCase))
            {
                return "ControlD";
            }

            if (host.Contains("adguard", StringComparison.OrdinalIgnoreCase))
            {
                return "AdGuard";
            }

            if (host.Contains("dnspod", StringComparison.OrdinalIgnoreCase))
            {
                return "DNSPod";
            }

            if (host.Contains("onedns", StringComparison.OrdinalIgnoreCase))
            {
                return "OneDNS";
            }

            if (host.Contains("safedns", StringComparison.OrdinalIgnoreCase))
            {
                return "SafeDNS";
            }

            if (host.Contains("yandex", StringComparison.OrdinalIgnoreCase))
            {
                return "Yandex.DNS";
            }

            if (host.Contains("freenom", StringComparison.OrdinalIgnoreCase))
            {
                return "Freenom World";
            }

            if (host.Contains("mullvad", StringComparison.OrdinalIgnoreCase))
            {
                return "Mullvad";
            }

            if (host.Contains("faelix", StringComparison.OrdinalIgnoreCase))
            {
                return "FAELIX";
            }

            if (host.Contains("digitale-gesellschaft", StringComparison.OrdinalIgnoreCase))
            {
                return "Digitale Gesellschaft";
            }

            if (host.Contains("dns.sb", StringComparison.OrdinalIgnoreCase)
                || host.Contains("dot.sb", StringComparison.OrdinalIgnoreCase))
            {
                return "DNS.SB";
            }

            if (host.Contains("applied-privacy", StringComparison.OrdinalIgnoreCase))
            {
                return "Applied Privacy";
            }

            if (host.Contains("iij", StringComparison.OrdinalIgnoreCase))
            {
                return "IIJ";
            }

            if (host.Contains("snopyta", StringComparison.OrdinalIgnoreCase))
            {
                return "Snopyta";
            }

            if (host.Contains("surfshark", StringComparison.OrdinalIgnoreCase))
            {
                return "Surfshark";
            }

            if (host.Contains("nextdns", StringComparison.OrdinalIgnoreCase))
            {
                return "NextDNS";
            }

            if (host.Contains("dnsforfamily", StringComparison.OrdinalIgnoreCase))
            {
                return "DNS For Family";
            }

            if (host.Contains("dnsfilter", StringComparison.OrdinalIgnoreCase))
            {
                return "DNSFilter";
            }

            if (host.Contains("gcore", StringComparison.OrdinalIgnoreCase))
            {
                return "Gcore";
            }

            if (host.Contains("dynect", StringComparison.OrdinalIgnoreCase)
                || host.Contains("oracle", StringComparison.OrdinalIgnoreCase))
            {
                return "Dyn (Oracle)";
            }

            if (host.Contains("ultradns", StringComparison.OrdinalIgnoreCase)
                || host.Contains("rdns1.ultradns", StringComparison.OrdinalIgnoreCase)
                || host.Contains("rdns2.ultradns", StringComparison.OrdinalIgnoreCase)
                || host.Contains("rec1pubns", StringComparison.OrdinalIgnoreCase))
            {
                return "UltraDNS";
            }

            if (host.Contains("hurricane", StringComparison.OrdinalIgnoreCase)
                || host.Contains("he.net", StringComparison.OrdinalIgnoreCase))
            {
                return "Hurricane Electric";
            }

            if (host.Contains(".cox.net", StringComparison.OrdinalIgnoreCase))
            {
                return "Cox";
            }
        }

        if (ipAddress is "194.242.2.2" or "194.242.2.3"
            || ipAddress.StartsWith("2a07:e340:", StringComparison.OrdinalIgnoreCase))
        {
            return "Mullvad";
        }

        if (ipAddress is "46.227.200.54" or "46.227.200.55"
            || ipAddress.StartsWith("2a01:9e00:", StringComparison.OrdinalIgnoreCase))
        {
            return "FAELIX";
        }

        if (ipAddress is "185.222.222.222" or "45.11.45.11"
            || string.Equals(ipAddress, "2a09::", StringComparison.OrdinalIgnoreCase)
            || string.Equals(ipAddress, "2a11::", StringComparison.OrdinalIgnoreCase))
        {
            return "DNS.SB";
        }

        if (ipAddress is "146.255.56.98"
            || ipAddress.StartsWith("2a12:dd47:1030:", StringComparison.OrdinalIgnoreCase))
        {
            return "Applied Privacy";
        }

        if (ipAddress is "103.2.57.5"
            || ipAddress.StartsWith("2404:1a8:7f01:a:", StringComparison.OrdinalIgnoreCase))
        {
            return "IIJ";
        }

        if (ipAddress is "194.169.169.169"
            || ipAddress.StartsWith("2a09:a707:", StringComparison.OrdinalIgnoreCase))
        {
            return "Surfshark";
        }

        if (ipAddress is "95.85.95.85" or "2.56.220.2"
            || ipAddress.StartsWith("2a03:90c0:", StringComparison.OrdinalIgnoreCase))
        {
            return "Gcore";
        }

        if (ipAddress is "216.146.35.35" or "216.146.36.36")
        {
            return "Dyn (Oracle)";
        }

        if (ipAddress is "64.6.64.6" or "64.6.65.6"
            || ipAddress.StartsWith("156.154.7", StringComparison.Ordinal))
        {
            return "UltraDNS";
        }

        if (ipAddress.StartsWith("1.1.", StringComparison.Ordinal)
            || ipAddress.StartsWith("1.0.", StringComparison.Ordinal)
            || ipAddress.StartsWith("2606:4700:", StringComparison.OrdinalIgnoreCase))
        {
            return "Cloudflare";
        }

        if (ipAddress.StartsWith("8.8.", StringComparison.Ordinal)
            || ipAddress.StartsWith("2001:4860:", StringComparison.OrdinalIgnoreCase))
        {
            return "Google";
        }

        if (ipAddress.StartsWith("9.9.", StringComparison.Ordinal)
            || ipAddress.StartsWith("149.112.", StringComparison.Ordinal)
            || ipAddress.StartsWith("2620:fe:", StringComparison.OrdinalIgnoreCase))
        {
            return "Quad9";
        }

        if (ipAddress.StartsWith("208.67.", StringComparison.Ordinal)
            || ipAddress.StartsWith("2620:0:cc", StringComparison.OrdinalIgnoreCase))
        {
            return "OpenDNS";
        }

        if (ipAddress.StartsWith("76.76.", StringComparison.Ordinal))
        {
            return "ControlD";
        }

        if (ipAddress.StartsWith("94.140.", StringComparison.Ordinal))
        {
            return "AdGuard";
        }

        if (ipAddress.StartsWith("64.6.6", StringComparison.Ordinal))
        {
            return "UltraDNS";
        }

        if (ipAddress.StartsWith("68.105.", StringComparison.Ordinal)
            || ipAddress.StartsWith("2001:578:3f:", StringComparison.OrdinalIgnoreCase))
        {
            return "Cox";
        }

        if (ipAddress.StartsWith("156.154.", StringComparison.Ordinal))
        {
            return "UltraDNS";
        }

        if (ipAddress.StartsWith("77.88.", StringComparison.Ordinal))
        {
            return "Yandex.DNS";
        }

        string? inferredProvider = BuildProviderFromHost(hostName);
        return string.IsNullOrWhiteSpace(inferredProvider) ? "Public DNS" : inferredProvider;
    }

    private static string? BuildProviderFromHost(string? hostName)
    {
        if (string.IsNullOrWhiteSpace(hostName))
        {
            return null;
        }

        string cleaned = hostName.Trim().Trim('.').ToLowerInvariant();
        if (cleaned.Length == 0 || cleaned.Contains("no official", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        string[] labels = cleaned.Split('.', StringSplitOptions.RemoveEmptyEntries);
        if (labels.Length == 0)
        {
            return null;
        }

        string stem = labels.Length >= 2 ? labels[^2] : labels[0];
        if (stem.Length < 2)
        {
            stem = labels[0];
        }

        return ToTitleCaseProvider(stem);
    }

    private static string ToTitleCaseProvider(string token)
    {
        string normalized = token
            .Replace("-", " ", StringComparison.Ordinal)
            .Replace("_", " ", StringComparison.Ordinal)
            .Trim();

        if (normalized.Length == 0)
        {
            return "Public DNS";
        }

        string[] words = normalized.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        for (int i = 0; i < words.Length; i++)
        {
            string word = words[i];
            words[i] = word.Length == 1
                ? word.ToUpperInvariant()
                : char.ToUpperInvariant(word[0]) + word[1..];
        }

        return string.Join(' ', words);
    }

    private sealed class PublicDnsEntry
    {
        [JsonPropertyName("ip")]
        public string? Ip { get; init; }

        [JsonPropertyName("name")]
        public string? Name { get; init; }

        [JsonPropertyName("reliability")]
        public double? Reliability { get; init; }
    }

    [JsonSourceGenerationOptions]
    [JsonSerializable(typeof(PublicDnsEntry[]))]
    private partial class DnsServerListJsonContext : JsonSerializerContext
    {
    }
}
