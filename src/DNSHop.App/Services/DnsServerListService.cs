using DNSHop.App.Models;
using System;
using System.Buffers.Binary;
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
    private const int MaxNormalizedServers = 420;
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

                var iniServers = LoadIniResolversFromFile(existingKeys, MaxNormalizedServers, cancellationToken);
                servers.AddRange(iniServers);

                var normalizedServers = NormalizeServerList(servers);
                AppDiagnostics.WriteInfo(
                    "Resolvers",
                    $"Loaded {normalizedServers.Count} local resolver endpoints ({iniServers.Count} from INI, fingerprint '{currentFingerprint}').");

                return normalizedServers;
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
            catch (Exception ex)
            {
                // Startup must remain reliable even if external feed is unavailable.
                AppDiagnostics.WriteWarning("Resolvers", $"Public resolver feed update failed during combined load: {ex.Message}");
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
            DnsServerDefinition.CreateUdpTcp("95.85.95.85", "Gcore"),
            DnsServerDefinition.CreateUdpTcp("2.56.220.2", "Gcore"),
            DnsServerDefinition.CreateUdpTcp("194.169.169.169", "Surfshark"),
            // Cox public resolver pair (ISP-assigned in many regions).
            DnsServerDefinition.CreateUdpTcp("68.105.28.16", "Cox"),
            DnsServerDefinition.CreateUdpTcp("68.105.29.16", "Cox"),
            DnsServerDefinition.CreateUdpTcp("216.146.35.35", "Dyn (Oracle)"),
            DnsServerDefinition.CreateUdpTcp("216.146.36.36", "Dyn (Oracle)"),
            DnsServerDefinition.CreateUdpTcp("64.6.64.6", "Verisign"),
            DnsServerDefinition.CreateUdpTcp("64.6.65.6", "Verisign"),
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

            // --- Additional verified public resolvers requested in issue triage ---
            DnsServerDefinition.CreateUdpTcp("5.1.66.255", "FFMUC"),
            DnsServerDefinition.CreateUdpTcp("185.150.99.255", "FFMUC"),
            DnsServerDefinition.CreateUdpTcp("2001:678:e68:f000::", "FFMUC"),
            DnsServerDefinition.CreateUdpTcp("2001:678:ed0:f000::", "FFMUC"),
            DnsServerDefinition.CreateDoh("https://doh.ffmuc.net/dns-query", "FFMUC"),
            DnsServerDefinition.CreateDot("dot.ffmuc.net", "dot.ffmuc.net", "FFMUC"),

            DnsServerDefinition.CreateUdpTcp("49.12.67.122", "dnsforge"),
            DnsServerDefinition.CreateUdpTcp("91.99.154.175", "dnsforge"),
            DnsServerDefinition.CreateUdpTcp("2a01:4f8:c013:29d::122", "dnsforge"),
            DnsServerDefinition.CreateUdpTcp("2a01:4f8:c010:8c35::175", "dnsforge"),
            DnsServerDefinition.CreateDoh("https://dnsforge.de/dns-query", "dnsforge"),
            DnsServerDefinition.CreateDot("dnsforge.de", "dnsforge.de", "dnsforge"),
            DnsServerDefinition.CreateDoh("https://clean.dnsforge.de/dns-query", "dnsforge Clean"),
            DnsServerDefinition.CreateDot("clean.dnsforge.de", "clean.dnsforge.de", "dnsforge Clean"),
            DnsServerDefinition.CreateDoh("https://hard.dnsforge.de/dns-query", "dnsforge Hard"),
            DnsServerDefinition.CreateDot("hard.dnsforge.de", "hard.dnsforge.de", "dnsforge Hard"),
            DnsServerDefinition.CreateDoh("https://blank.dnsforge.de/dns-query", "dnsforge Blank"),
            DnsServerDefinition.CreateDot("blank.dnsforge.de", "blank.dnsforge.de", "dnsforge Blank"),

            DnsServerDefinition.CreateDoh("https://wikimedia-dns.org/dns-query", "Wikimedia DNS"),
            DnsServerDefinition.CreateDot("wikimedia-dns.org", "wikimedia-dns.org", "Wikimedia DNS"),

            DnsServerDefinition.CreateUdpTcp("96.45.45.45", "FortiGuard (managed)"),
            DnsServerDefinition.CreateUdpTcp("96.45.46.46", "FortiGuard (managed)"),
            DnsServerDefinition.CreateDot("96.45.45.45", "globalsdns.fortinet.net", "FortiGuard (managed)"),
            DnsServerDefinition.CreateDot("96.45.46.46", "globalsdns.fortinet.net", "FortiGuard (managed)"),

            DnsServerDefinition.CreateUdpTcp("54.174.40.213", "WatchGuard DNSWatch (managed)"),
            DnsServerDefinition.CreateUdpTcp("52.3.100.184", "WatchGuard DNSWatch (managed)"),
            DnsServerDefinition.CreateUdpTcp("34.240.115.208", "WatchGuard DNSWatch (managed)"),
            DnsServerDefinition.CreateUdpTcp("34.251.171.117", "WatchGuard DNSWatch (managed)"),
            DnsServerDefinition.CreateUdpTcp("54.199.61.196", "WatchGuard DNSWatch (managed)"),
            DnsServerDefinition.CreateUdpTcp("176.34.8.52", "WatchGuard DNSWatch (managed)"),
            DnsServerDefinition.CreateUdpTcp("13.237.104.38", "WatchGuard DNSWatch (managed)"),
            DnsServerDefinition.CreateUdpTcp("13.237.109.176", "WatchGuard DNSWatch (managed)"),

            // --- CIRA Canadian Shield (Canada) ---
            DnsServerDefinition.CreateUdpTcp("149.112.121.10", "CIRA Canadian Shield"),
            DnsServerDefinition.CreateUdpTcp("149.112.122.10", "CIRA Canadian Shield"),
            DnsServerDefinition.CreateUdpTcp("2620:10a:80bb::10", "CIRA Canadian Shield"),
            DnsServerDefinition.CreateUdpTcp("2620:10a:80bc::10", "CIRA Canadian Shield"),
            DnsServerDefinition.CreateDoh("https://private.canadianshield.cira.ca/dns-query", "CIRA Canadian Shield"),
            DnsServerDefinition.CreateDot("private.canadianshield.cira.ca", "private.canadianshield.cira.ca", "CIRA Canadian Shield"),
            DnsServerDefinition.CreateUdpTcp("149.112.121.20", "CIRA Canadian Shield Protected"),
            DnsServerDefinition.CreateUdpTcp("149.112.122.20", "CIRA Canadian Shield Protected"),
            DnsServerDefinition.CreateDoh("https://protected.canadianshield.cira.ca/dns-query", "CIRA Canadian Shield Protected"),
            DnsServerDefinition.CreateDot("protected.canadianshield.cira.ca", "protected.canadianshield.cira.ca", "CIRA Canadian Shield Protected"),
            DnsServerDefinition.CreateUdpTcp("149.112.121.30", "CIRA Canadian Shield Family"),
            DnsServerDefinition.CreateUdpTcp("149.112.122.30", "CIRA Canadian Shield Family"),
            DnsServerDefinition.CreateDoh("https://family.canadianshield.cira.ca/dns-query", "CIRA Canadian Shield Family"),
            DnsServerDefinition.CreateDot("family.canadianshield.cira.ca", "family.canadianshield.cira.ca", "CIRA Canadian Shield Family"),

            // --- DNS4EU (European Union public resolver) ---
            DnsServerDefinition.CreateUdpTcp("86.54.11.1", "DNS4EU"),
            DnsServerDefinition.CreateUdpTcp("86.54.11.201", "DNS4EU"),
            DnsServerDefinition.CreateUdpTcp("2a13:1001::86:54:11:1", "DNS4EU"),
            DnsServerDefinition.CreateDoh("https://protective.joindns4.eu/dns-query", "DNS4EU"),
            DnsServerDefinition.CreateDot("protective.joindns4.eu", "protective.joindns4.eu", "DNS4EU"),
            DnsServerDefinition.CreateUdpTcp("86.54.11.13", "DNS4EU No-Ads"),
            DnsServerDefinition.CreateDoh("https://noads.joindns4.eu/dns-query", "DNS4EU No-Ads"),
            DnsServerDefinition.CreateDot("noads.joindns4.eu", "noads.joindns4.eu", "DNS4EU No-Ads"),
            DnsServerDefinition.CreateUdpTcp("86.54.11.12", "DNS4EU Child"),
            DnsServerDefinition.CreateDoh("https://child.joindns4.eu/dns-query", "DNS4EU Child"),
            DnsServerDefinition.CreateDot("child.joindns4.eu", "child.joindns4.eu", "DNS4EU Child"),
            DnsServerDefinition.CreateUdpTcp("86.54.11.100", "DNS4EU Unfiltered"),
            DnsServerDefinition.CreateDoh("https://unfiltered.joindns4.eu/dns-query", "DNS4EU Unfiltered"),
            DnsServerDefinition.CreateDot("unfiltered.joindns4.eu", "unfiltered.joindns4.eu", "DNS4EU Unfiltered"),

            // --- RethinkDNS (serverless, configurable blocklists) ---
            DnsServerDefinition.CreateDoh("https://sky.rethinkdns.com/dns-query", "RethinkDNS Sky"),
            DnsServerDefinition.CreateDoh("https://max.rethinkdns.com/dns-query", "RethinkDNS Max"),
            DnsServerDefinition.CreateDot("sky.rethinkdns.com", "sky.rethinkdns.com", "RethinkDNS Sky"),
            DnsServerDefinition.CreateDot("max.rethinkdns.com", "max.rethinkdns.com", "RethinkDNS Max"),

            // --- OpenBLD.net (ad / tracker / malware blocking, DoH+DoT only) ---
            DnsServerDefinition.CreateDoh("https://ada.openbld.net/dns-query", "OpenBLD"),
            DnsServerDefinition.CreateDot("ada.openbld.net", "ada.openbld.net", "OpenBLD"),
            DnsServerDefinition.CreateDoh("https://ric.openbld.net/dns-query", "OpenBLD Strict"),
            DnsServerDefinition.CreateDot("ric.openbld.net", "ric.openbld.net", "OpenBLD Strict"),

            // --- RESTENA (Luxembourg) ---
            DnsServerDefinition.CreateUdpTcp("158.64.1.29", "RESTENA"),
            DnsServerDefinition.CreateUdpTcp("2001:a18:1::29", "RESTENA"),
            DnsServerDefinition.CreateDoh("https://dnspub.restena.lu/dns-query", "RESTENA"),
            DnsServerDefinition.CreateDot("dnspub.restena.lu", "dnspub.restena.lu", "RESTENA"),

            // --- LibreDNS (LibreOps) ---
            DnsServerDefinition.CreateUdpTcp("116.202.176.26", "LibreDNS"),
            DnsServerDefinition.CreateUdpTcp("2a01:4f8:1c0c:8274::1", "LibreDNS"),
            DnsServerDefinition.CreateDoh("https://doh.libredns.gr/dns-query", "LibreDNS"),
            DnsServerDefinition.CreateDoh("https://doh.libredns.gr/noads", "LibreDNS No-Ads"),
            DnsServerDefinition.CreateDot("dot.libredns.gr", "dot.libredns.gr", "LibreDNS"),

            // --- SWITCH Public DNS (Switzerland) ---
            DnsServerDefinition.CreateUdpTcp("130.59.31.248", "SWITCH"),
            DnsServerDefinition.CreateUdpTcp("130.59.31.251", "SWITCH"),
            DnsServerDefinition.CreateUdpTcp("2001:620:0:ff::2", "SWITCH"),
            DnsServerDefinition.CreateUdpTcp("2001:620:0:ff::3", "SWITCH"),
            DnsServerDefinition.CreateDoh("https://dns.switch.ch/dns-query", "SWITCH"),
            DnsServerDefinition.CreateDot("dns.switch.ch", "dns.switch.ch", "SWITCH"),

            // --- Mullvad (additional filtered profiles over DoH + DoT) ---
            DnsServerDefinition.CreateDoh("https://base.dns.mullvad.net/dns-query", "Mullvad Base"),
            DnsServerDefinition.CreateDot("base.dns.mullvad.net", "base.dns.mullvad.net", "Mullvad Base"),
            DnsServerDefinition.CreateDoh("https://extended.dns.mullvad.net/dns-query", "Mullvad Extended"),
            DnsServerDefinition.CreateDot("extended.dns.mullvad.net", "extended.dns.mullvad.net", "Mullvad Extended"),
            DnsServerDefinition.CreateDoh("https://family.dns.mullvad.net/dns-query", "Mullvad Family"),
            DnsServerDefinition.CreateDot("family.dns.mullvad.net", "family.dns.mullvad.net", "Mullvad Family"),
            DnsServerDefinition.CreateDoh("https://all.dns.mullvad.net/dns-query", "Mullvad All"),
            DnsServerDefinition.CreateDot("all.dns.mullvad.net", "all.dns.mullvad.net", "Mullvad All"),

            // --- NordVPN (Nord Threat Protection public encrypted DNS) ---
            // CyberSec: blocks ads, malware and tracking.
            DnsServerDefinition.CreateUdpTcp("103.86.96.108", "NordVPN CyberSec"),
            DnsServerDefinition.CreateUdpTcp("103.86.99.108", "NordVPN CyberSec"),
            DnsServerDefinition.CreateDoh("https://dns-cybersec.nordthreatprotection.com/dns-query", "NordVPN CyberSec"),
            DnsServerDefinition.CreateDot("dns-cybersec.nordthreatprotection.com", "dns-cybersec.nordthreatprotection.com", "NordVPN CyberSec"),
            DnsServerDefinition.CreateDoq("dns-cybersec.nordthreatprotection.com", "NordVPN CyberSec"),
            // MalwareSec: blocks malware only (allows ads).
            DnsServerDefinition.CreateUdpTcp("103.86.96.107", "NordVPN MalwareSec"),
            DnsServerDefinition.CreateUdpTcp("103.86.99.107", "NordVPN MalwareSec"),
            DnsServerDefinition.CreateDoh("https://dns-malwaresec.nordthreatprotection.com/dns-query", "NordVPN MalwareSec"),
            DnsServerDefinition.CreateDot("dns-malwaresec.nordthreatprotection.com", "dns-malwaresec.nordthreatprotection.com", "NordVPN MalwareSec"),
            DnsServerDefinition.CreateDoq("dns-malwaresec.nordthreatprotection.com", "NordVPN MalwareSec"),
            // Family: blocks ads, malware and adult content.
            DnsServerDefinition.CreateUdpTcp("103.86.96.111", "NordVPN Family"),
            DnsServerDefinition.CreateUdpTcp("103.86.99.111", "NordVPN Family"),
            DnsServerDefinition.CreateDoh("https://dns-adultsites-cybersec.nordthreatprotection.com/dns-query", "NordVPN Family"),
            DnsServerDefinition.CreateDot("dns-adultsites-cybersec.nordthreatprotection.com", "dns-adultsites-cybersec.nordthreatprotection.com", "NordVPN Family"),
            DnsServerDefinition.CreateDoq("dns-adultsites-cybersec.nordthreatprotection.com", "NordVPN Family"),
            // Standard NordVPN resolver pair (no third-party filtering).
            DnsServerDefinition.CreateUdpTcp("103.86.96.100", "NordVPN"),
            DnsServerDefinition.CreateUdpTcp("103.86.99.100", "NordVPN"),

            // --- ControlD (free unfiltered resolver, "more public than public") ---
            DnsServerDefinition.CreateUdpTcp("76.76.2.0", "ControlD Unfiltered"),
            DnsServerDefinition.CreateUdpTcp("76.76.10.0", "ControlD Unfiltered"),
            DnsServerDefinition.CreateDoh("https://freedns.controld.com/p0", "ControlD Unfiltered"),
            DnsServerDefinition.CreateDot("p0.freedns.controld.com", "p0.freedns.controld.com", "ControlD Unfiltered"),
            DnsServerDefinition.CreateDoq("p0.freedns.controld.com", "ControlD Unfiltered"),

            // --- UncensoredDNS (Denmark, no filtering or logging) ---
            DnsServerDefinition.CreateUdpTcp("2001:67c:28a4::", "UncensoredDNS"),
            DnsServerDefinition.CreateDoh("https://anycast.uncensoreddns.org/dns-query", "UncensoredDNS"),
            DnsServerDefinition.CreateDot("anycast.uncensoreddns.org", "anycast.uncensoreddns.org", "UncensoredDNS"),
            DnsServerDefinition.CreateUdpTcp("2a01:3a0:53:53::", "UncensoredDNS Unicast"),
            DnsServerDefinition.CreateDoh("https://unicast.uncensoreddns.org/dns-query", "UncensoredDNS Unicast"),
            DnsServerDefinition.CreateDot("unicast.uncensoreddns.org", "unicast.uncensoreddns.org", "UncensoredDNS Unicast"),

            // --- Digitalcourage (Germany, censorship-free). DoT only: the operator does not run
            // this resolver on port 53, so there is deliberately no plain-DNS entry. The IP-addressed
            // DoT entry still works when the bootstrap lookup of the hostname itself is blocked. ---
            DnsServerDefinition.CreateDot("dns3.digitalcourage.de", "dns3.digitalcourage.de", "Digitalcourage"),
            DnsServerDefinition.CreateDot("5.9.164.112", "dns3.digitalcourage.de", "Digitalcourage"),

            // --- Artikel10 e.V. (Germany, non-profit, no query logging) ---
            DnsServerDefinition.CreateUdpTcp("217.197.91.153", "Artikel10"),
            DnsServerDefinition.CreateUdpTcp("2001:67c:1401:2120::1", "Artikel10"),
            DnsServerDefinition.CreateDoh("https://dns.artikel10.org/dns-query", "Artikel10"),
            DnsServerDefinition.CreateDot("dns.artikel10.org", "dns.artikel10.org", "Artikel10"),

            // --- DNSFilter ---
            DnsServerDefinition.CreateUdpTcp("103.247.36.36", "DNSFilter"),
            DnsServerDefinition.CreateUdpTcp("103.247.37.37", "DNSFilter"),
            DnsServerDefinition.CreateUdpTcp("2402:5c40:5c40::3636", "DNSFilter"),
            DnsServerDefinition.CreateUdpTcp("2402:5c40:5c41::3737", "DNSFilter"),

            // --- FlashStart (Italy) ---
            DnsServerDefinition.CreateUdpTcp("185.236.104.104", "FlashStart"),
            DnsServerDefinition.CreateUdpTcp("185.236.105.105", "FlashStart"),
            DnsServerDefinition.CreateUdpTcp("2a12:7bc0:104:104::", "FlashStart"),
            DnsServerDefinition.CreateUdpTcp("2a12:7bc0:105:105::", "FlashStart"),

            // --- Cloudflare filtered variants ---
            DnsServerDefinition.CreateUdpTcp("1.1.1.2", "Cloudflare Security"),
            DnsServerDefinition.CreateUdpTcp("1.0.0.2", "Cloudflare Security"),
            DnsServerDefinition.CreateDoh("https://security.cloudflare-dns.com/dns-query", "Cloudflare Security"),
            DnsServerDefinition.CreateDot("security.cloudflare-dns.com", "security.cloudflare-dns.com", "Cloudflare Security"),
            DnsServerDefinition.CreateUdpTcp("1.1.1.3", "Cloudflare Family"),
            DnsServerDefinition.CreateUdpTcp("1.0.0.3", "Cloudflare Family"),
            DnsServerDefinition.CreateDoh("https://family.cloudflare-dns.com/dns-query", "Cloudflare Family"),
            DnsServerDefinition.CreateDot("family.cloudflare-dns.com", "family.cloudflare-dns.com", "Cloudflare Family"),
            DnsServerDefinition.CreateDoh("https://dns64.cloudflare-dns.com/dns-query", "Cloudflare DNS64"),
            DnsServerDefinition.CreateDoh("https://dns64.dns.google/dns-query", "Google DNS64"),

            // --- CleanBrowsing (filter tiers) ---
            DnsServerDefinition.CreateUdpTcp("185.228.168.9", "CleanBrowsing Security"),
            DnsServerDefinition.CreateUdpTcp("185.228.169.9", "CleanBrowsing Security"),
            DnsServerDefinition.CreateDoh("https://doh.cleanbrowsing.org/doh/security-filter/", "CleanBrowsing Security"),
            DnsServerDefinition.CreateUdpTcp("185.228.168.168", "CleanBrowsing Family"),
            DnsServerDefinition.CreateUdpTcp("185.228.169.168", "CleanBrowsing Family"),
            DnsServerDefinition.CreateDoh("https://doh.cleanbrowsing.org/doh/family-filter/", "CleanBrowsing Family"),
            DnsServerDefinition.CreateUdpTcp("185.228.168.10", "CleanBrowsing Adult"),
            DnsServerDefinition.CreateUdpTcp("185.228.169.11", "CleanBrowsing Adult"),
            DnsServerDefinition.CreateDoh("https://doh.cleanbrowsing.org/doh/adult-filter/", "CleanBrowsing Adult"),

            // --- ControlD additional free profiles (uncensored bypasses upstream blocklists) ---
            DnsServerDefinition.CreateDoh("https://freedns.controld.com/uncensored", "ControlD Uncensored"),
            DnsServerDefinition.CreateDot("uncensored.freedns.controld.com", "uncensored.freedns.controld.com", "ControlD Uncensored"),
            DnsServerDefinition.CreateDoq("uncensored.freedns.controld.com", "ControlD Uncensored"),
            DnsServerDefinition.CreateDoh("https://freedns.controld.com/p1", "ControlD Ad Blocking"),
            DnsServerDefinition.CreateDot("p1.freedns.controld.com", "p1.freedns.controld.com", "ControlD Ad Blocking"),
            DnsServerDefinition.CreateDoh("https://freedns.controld.com/p2", "ControlD Ads + Tracking"),
            DnsServerDefinition.CreateDot("p2.freedns.controld.com", "p2.freedns.controld.com", "ControlD Ads + Tracking"),
            DnsServerDefinition.CreateDoh("https://freedns.controld.com/family", "ControlD Family"),
            DnsServerDefinition.CreateDot("family.freedns.controld.com", "family.freedns.controld.com", "ControlD Family"),

            // --- National / research-network resolvers (curl DoH list) ---
            DnsServerDefinition.CreateUdpTcp("193.17.47.1", "CZ.NIC ODVR"),
            DnsServerDefinition.CreateUdpTcp("185.43.135.1", "CZ.NIC ODVR"),
            DnsServerDefinition.CreateDoh("https://odvr.nic.cz/dns-query", "CZ.NIC ODVR"),
            DnsServerDefinition.CreateDot("odvr.nic.cz", "odvr.nic.cz", "CZ.NIC ODVR"),
            DnsServerDefinition.CreateDoh("https://dns.cert.ee/dns-query", "CERT Estonia"),
            DnsServerDefinition.CreateDot("dns.cert.ee", "dns.cert.ee", "CERT Estonia"),
            DnsServerDefinition.CreateDoh("https://dns.belnet.be/dns-query", "Belnet"),
            DnsServerDefinition.CreateDoh("https://doh.dns4all.eu/dns-query", "DNS4all"),
            DnsServerDefinition.CreateDoh("https://resolver.sunet.se/dns-query", "Sunet"),
            DnsServerDefinition.CreateDoh("https://doh.lv/dns-query", "NIC.LV"),
            DnsServerDefinition.CreateDoh("https://doh.domreg.lt/dns-query", "domreg.lt"),
            DnsServerDefinition.CreateDoh("https://dns.aa.net.uk/dns-query", "Andrews & Arnold"),

            // --- FDN (French Data Network): open recursive resolvers run explicitly as an
            // anti-censorship measure. Metadata existed for these but the endpoints themselves
            // were never in the list, so they were never actually benchmarked. ---
            DnsServerDefinition.CreateUdpTcp("80.67.169.12", "FDN"),
            DnsServerDefinition.CreateUdpTcp("80.67.169.40", "FDN"),
            DnsServerDefinition.CreateUdpTcp("2001:910:800::12", "FDN"),
            DnsServerDefinition.CreateUdpTcp("2001:910:800::40", "FDN"),
            DnsServerDefinition.CreateDoh("https://ns0.fdn.fr/dns-query", "FDN"),
            DnsServerDefinition.CreateDoh("https://ns1.fdn.fr/dns-query", "FDN"),
            DnsServerDefinition.CreateDot("ns0.fdn.fr", "ns0.fdn.fr", "FDN"),
            DnsServerDefinition.CreateDot("ns1.fdn.fr", "ns1.fdn.fr", "FDN"),

            // --- Independent / association-run resolvers (curl DoH list) ---
            DnsServerDefinition.CreateDoh("https://dns.w3ctag.org/dns-query", "W3C TAG"),
            DnsServerDefinition.CreateDoh("https://doh.lacontrevoie.fr/dns-query", "La Contre-Voie"),
            DnsServerDefinition.CreateDoh("https://dns.aquilenet.fr/dns-query", "Aquilenet"),
            DnsServerDefinition.CreateDoh("https://dns.hostux.net/dns-query", "Hostux"),
            DnsServerDefinition.CreateDoh("https://dns.hostux.net/ads", "Hostux No-Ads"),
            DnsServerDefinition.CreateDoh("https://dns.njal.la/dns-query", "Njalla"),
            DnsServerDefinition.CreateDoh("https://dns.comss.one/dns-query", "Comss.one"),
            DnsServerDefinition.CreateDoh("https://adfree.usableprivacy.net/dns-query", "Usable Privacy"),
            DnsServerDefinition.CreateDoh("https://dns.telekom.de/dns-query", "Telekom"),
            DnsServerDefinition.CreateDoh("https://doh.seby.io/dns-query", "Seby"),
            DnsServerDefinition.CreateDoh("https://doh.tiar.app/dns-query", "Tiarap"),
            DnsServerDefinition.CreateDoh("https://dns1.in-berlin.de/dns-query", "In-Berlin"),
            DnsServerDefinition.CreateDoh("https://dns2.in-berlin.de/dns-query", "In-Berlin"),
            DnsServerDefinition.CreateDoh("https://dns.dnshome.de/dns-query", "dnsHome.de"),
            DnsServerDefinition.CreateDoh("https://dns.kernel-error.de/dns-query", "Kernel Error"),
            DnsServerDefinition.CreateDoh("https://doh.disconnect.app/dns-query", "Disconnect"),
            DnsServerDefinition.CreateDoh("https://rfree1.blue-shield.at/dns-query", "Blue Shield Umbrella"),
            DnsServerDefinition.CreateDoh("https://rfree2.blue-shield.at/dns-query", "Blue Shield Umbrella"),
            DnsServerDefinition.CreateDoh("https://dns12.quad9.net/dns-query", "Quad9 (ECS, malware)"),
            DnsServerDefinition.CreateDoh("https://child-noads.joindns4.eu/dns-query", "DNS4EU Child No-Ads"),

            // --- DNS over QUIC (RFC 9250) ---
            DnsServerDefinition.CreateDoq("dns.quad9.net", "Quad9"),
            DnsServerDefinition.CreateDoq("dns9.quad9.net", "Quad9 (No ECS)"),
            DnsServerDefinition.CreateDoq("dns10.quad9.net", "Quad9 Unsecured"),
            DnsServerDefinition.CreateDoq("dns11.quad9.net", "Quad9 (ECS)"),
            DnsServerDefinition.CreateDoq("dns.adguard-dns.com", "AdGuard"),
            DnsServerDefinition.CreateDoq("unfiltered.adguard-dns.com", "AdGuard Unfiltered"),
            DnsServerDefinition.CreateDoq("family.adguard-dns.com", "AdGuard Family"),
            DnsServerDefinition.CreateDoq("dns0.eu", "DNS0.EU"),
            DnsServerDefinition.CreateDoq("zero.dns0.eu", "DNS0.EU Zero"),
            DnsServerDefinition.CreateDoq("open.dns0.eu", "DNS0.EU Open"),
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

        AppDiagnostics.WriteInfo(
            "Resolvers",
            $"Fetched {servers.Count} public resolver endpoints from remote feed '{PublicResolverFeed}'.");

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

            if (host.Contains("ffmuc", StringComparison.OrdinalIgnoreCase))
            {
                return "FFMUC";
            }

            if (host.Contains("dnsforge", StringComparison.OrdinalIgnoreCase))
            {
                return "dnsforge";
            }

            if (host.Contains("wikimedia-dns", StringComparison.OrdinalIgnoreCase))
            {
                return "Wikimedia DNS";
            }

            if (host.Contains("fortiguard", StringComparison.OrdinalIgnoreCase)
                || host.Contains("fortinet", StringComparison.OrdinalIgnoreCase)
                || host.Contains("globalsdns", StringComparison.OrdinalIgnoreCase))
            {
                return "FortiGuard (managed)";
            }

            if (host.Contains("dnswatch", StringComparison.OrdinalIgnoreCase)
                || host.Contains("watchguard", StringComparison.OrdinalIgnoreCase))
            {
                return "WatchGuard DNSWatch (managed)";
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

            if (host.Contains("verisign", StringComparison.OrdinalIgnoreCase))
            {
                return "Verisign";
            }

            if (host.Contains("fdn.fr", StringComparison.OrdinalIgnoreCase))
            {
                return "FDN";
            }

            if (host.Contains("uncensoreddns", StringComparison.OrdinalIgnoreCase))
            {
                return "UncensoredDNS";
            }

            if (host.Contains("digitalcourage", StringComparison.OrdinalIgnoreCase))
            {
                return "Digitalcourage";
            }

            if (host.Contains("artikel10", StringComparison.OrdinalIgnoreCase))
            {
                return "Artikel10";
            }

            if (host.Contains("flashstart", StringComparison.OrdinalIgnoreCase))
            {
                return "FlashStart";
            }

            if (host.Contains("cleanbrowsing", StringComparison.OrdinalIgnoreCase))
            {
                return "CleanBrowsing";
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

        if (ipAddress is "5.1.66.255" or "185.150.99.255"
            || string.Equals(ipAddress, "2001:678:e68:f000::", StringComparison.OrdinalIgnoreCase)
            || string.Equals(ipAddress, "2001:678:ed0:f000::", StringComparison.OrdinalIgnoreCase))
        {
            return "FFMUC";
        }

        if (ipAddress is "49.12.67.122" or "91.99.154.175" or "49.12.223.2" or "49.12.43.208"
            or "49.12.222.213" or "88.198.122.154" or "138.199.149.249" or "78.47.71.194"
            || string.Equals(ipAddress, "2a01:4f8:c013:29d::122", StringComparison.OrdinalIgnoreCase)
            || string.Equals(ipAddress, "2a01:4f8:c010:8c35::175", StringComparison.OrdinalIgnoreCase)
            || string.Equals(ipAddress, "2a01:4f8:c17:4fbc::2", StringComparison.OrdinalIgnoreCase)
            || string.Equals(ipAddress, "2a01:4f8:c012:ed89::208", StringComparison.OrdinalIgnoreCase)
            || string.Equals(ipAddress, "2a01:4f8:c17:2c61::213", StringComparison.OrdinalIgnoreCase)
            || string.Equals(ipAddress, "2a01:4f8:c013:5ec0::154", StringComparison.OrdinalIgnoreCase)
            || string.Equals(ipAddress, "2a01:4f8:c17:7aa5::249", StringComparison.OrdinalIgnoreCase)
            || string.Equals(ipAddress, "2a01:4f8:c013:aae9::194", StringComparison.OrdinalIgnoreCase))
        {
            return "dnsforge";
        }

        if (ipAddress is "96.45.45.45" or "96.45.46.46")
        {
            return "FortiGuard (managed)";
        }

        if (ipAddress is "185.71.138.138"
            || string.Equals(ipAddress, "2001:67c:930::1", StringComparison.OrdinalIgnoreCase))
        {
            return "Wikimedia DNS";
        }

        if (ipAddress is "54.174.40.213" or "52.3.100.184" or "34.240.115.208" or "34.251.171.117"
            or "54.199.61.196" or "176.34.8.52" or "13.237.104.38" or "13.237.109.176")
        {
            return "WatchGuard DNSWatch (managed)";
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

        // 64.6.64.6/64.6.65.6 are Verisign Public DNS; UltraDNS (Neustar) is the 156.154.7x pair.
        if (ipAddress is "64.6.64.6" or "64.6.65.6")
        {
            return "Verisign";
        }

        if (ipAddress.StartsWith("156.154.7", StringComparison.Ordinal))
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

        if (ipAddress.StartsWith("103.86.96.", StringComparison.Ordinal)
            || ipAddress.StartsWith("103.86.99.", StringComparison.Ordinal))
        {
            return "NordVPN";
        }

        if (ipAddress is "91.239.100.100" or "89.233.43.71"
            || ipAddress.StartsWith("2001:67c:28a4:", StringComparison.OrdinalIgnoreCase)
            || ipAddress.StartsWith("2a01:3a0:53:", StringComparison.OrdinalIgnoreCase))
        {
            return "UncensoredDNS";
        }

        if (ipAddress is "5.9.164.112" || ipAddress.StartsWith("2a01:4f8:251:554:", StringComparison.OrdinalIgnoreCase))
        {
            return "Digitalcourage";
        }

        if (ipAddress is "217.197.91.153" || ipAddress.StartsWith("2001:67c:1401:2120:", StringComparison.OrdinalIgnoreCase))
        {
            return "Artikel10";
        }

        if (ipAddress.StartsWith("185.228.168.", StringComparison.Ordinal)
            || ipAddress.StartsWith("185.228.169.", StringComparison.Ordinal))
        {
            return "CleanBrowsing";
        }

        if (ipAddress.StartsWith("185.236.104.", StringComparison.Ordinal)
            || ipAddress.StartsWith("185.236.105.", StringComparison.Ordinal))
        {
            return "FlashStart";
        }

        if (ipAddress.StartsWith("103.247.36.", StringComparison.Ordinal)
            || ipAddress.StartsWith("103.247.37.", StringComparison.Ordinal))
        {
            return "DNSFilter";
        }

        if (ipAddress is "193.17.47.1" or "185.43.135.1")
        {
            return "CZ.NIC ODVR";
        }

        if (ipAddress is "80.67.169.12" or "80.67.169.40"
            || ipAddress.StartsWith("2001:910:800:", StringComparison.OrdinalIgnoreCase))
        {
            return "FDN";
        }

        if (ipAddress.StartsWith("94.140.", StringComparison.Ordinal))
        {
            return "AdGuard";
        }

        if (ipAddress.StartsWith("64.6.6", StringComparison.Ordinal))
        {
            return "Verisign";
        }

        if (ipAddress.StartsWith("2001:578:3f:", StringComparison.OrdinalIgnoreCase))
        {
            return "Cox";
        }

        // ISP-operated resolvers that publish no reverse DNS name, so they cannot be identified by
        // hostname and would otherwise fall through to the generic "Public DNS" label.
        string? networkOwner = LookupNetworkOwner(ipAddress);
        if (networkOwner is not null)
        {
            return networkOwner;
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

    // IPv4 networks belonging to operators whose resolvers have no reverse DNS name. Ordered
    // longest-prefix-first is unnecessary here because the ranges do not overlap.
    private static readonly (string Network, int PrefixLength, string Provider)[] NetworkOwners =
    [
        // Cox Communications
        ("68.1.0.0", 16, "Cox"),
        ("68.2.0.0", 15, "Cox"),
        ("68.4.0.0", 14, "Cox"),
        ("68.8.0.0", 14, "Cox"),
        ("68.12.0.0", 15, "Cox"),
        ("68.96.0.0", 13, "Cox"),
        ("68.104.0.0", 14, "Cox"),
        ("68.108.0.0", 14, "Cox"),
        ("70.160.0.0", 11, "Cox"),
        ("72.192.0.0", 11, "Cox"),
        ("98.160.0.0", 12, "Cox"),
        ("24.248.0.0", 16, "Cox"),
        // Comcast
        ("68.86.0.0", 15, "Comcast"),
        ("75.75.0.0", 16, "Comcast"),
        // Norton ConnectSafe (legacy Symantec addresses)
        ("198.153.192.0", 18, "Norton ConnectSafe"),
        // Suddenlink (Optimum)
        ("209.55.0.0", 16, "Suddenlink"),
        // ThreatTrack Security
        ("74.118.212.0", 22, "ThreatTrack Security"),
    ];

    /// <summary>
    /// Map an IPv4 address to the operator of its network, if known.
    /// </summary>
    private static string? LookupNetworkOwner(string ipAddress)
    {
        if (!IPAddress.TryParse(ipAddress, out var parsed)
            || parsed.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
        {
            return null;
        }

        Span<byte> addressBytes = stackalloc byte[4];
        if (!parsed.TryWriteBytes(addressBytes, out _))
        {
            return null;
        }

        uint address = BinaryPrimitives.ReadUInt32BigEndian(addressBytes);

        // Reused across iterations: allocating inside the loop risks exhausting the stack (CA2014).
        Span<byte> networkBytes = stackalloc byte[4];

        foreach (var (network, prefixLength, provider) in NetworkOwners)
        {
            if (!IPAddress.TryParse(network, out var networkAddress)
                || !networkAddress.TryWriteBytes(networkBytes, out _))
            {
                continue;
            }

            uint mask = prefixLength == 0 ? 0u : uint.MaxValue << (32 - prefixLength);
            if ((address & mask) == (BinaryPrimitives.ReadUInt32BigEndian(networkBytes) & mask))
            {
                return provider;
            }
        }

        return null;
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
