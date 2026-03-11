using DNSHop.App.ViewModels;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace DNSHop.App.Services;

internal sealed class CurrentDnsStatusService
{
    private static readonly Regex ServerLineRegex = new(@"^\s*Server:\s*(.+)$", RegexOptions.Multiline | RegexOptions.Compiled);
    private static readonly Regex AddressLineRegex = new(@"^\s*Address:\s*(.+)$", RegexOptions.Multiline | RegexOptions.Compiled);
    private static readonly Regex ResolvectlCurrentDnsRegex = new(@"^\s*Current DNS Server:\s*(.+)$", RegexOptions.Multiline | RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex ResolvectlDnsServersRegex = new(@"^\s*DNS Servers:\s*(.+)$", RegexOptions.Multiline | RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public async Task<CurrentDnsSnapshot> GetSnapshotAsync(CancellationToken cancellationToken)
    {
        var adapters = new List<CurrentDnsAdapterViewModel>();

        foreach (var networkInterface in NetworkInterface.GetAllNetworkInterfaces()
                     .OrderByDescending(static networkInterface => networkInterface.OperationalStatus == OperationalStatus.Up)
                     .ThenBy(static networkInterface => networkInterface.Name, StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();

            IPInterfaceProperties properties = networkInterface.GetIPProperties();
            string gateways = JoinAddresses(properties.GatewayAddresses.Select(static gateway => gateway.Address));
            string dnsServersV4 = JoinAddresses(properties.DnsAddresses.Where(static address => address.AddressFamily == AddressFamily.InterNetwork));
            string dnsServersV6 = JoinAddresses(properties.DnsAddresses.Where(static address => address.AddressFamily == AddressFamily.InterNetworkV6));

            string ipv4Mode = await GetDnsModeAsync(
                AddressFamily.InterNetwork,
                networkInterface.Name,
                dnsServersV4,
                cancellationToken).ConfigureAwait(false);

            string ipv6Mode = await GetDnsModeAsync(
                AddressFamily.InterNetworkV6,
                networkInterface.Name,
                dnsServersV6,
                cancellationToken).ConfigureAwait(false);

            adapters.Add(new CurrentDnsAdapterViewModel
            {
                InterfaceName = networkInterface.Name,
                Status = networkInterface.OperationalStatus.ToString(),
                TrafficRole = networkInterface.OperationalStatus == OperationalStatus.Up && !string.IsNullOrWhiteSpace(gateways)
                    ? "Active route"
                    : "Other",
                GatewaySummary = string.IsNullOrWhiteSpace(gateways) ? "None" : gateways,
                Ipv4Mode = ipv4Mode,
                Ipv4Servers = string.IsNullOrWhiteSpace(dnsServersV4) ? "None" : dnsServersV4,
                Ipv6Mode = ipv6Mode,
                Ipv6Servers = string.IsNullOrWhiteSpace(dnsServersV6) ? "None" : dnsServersV6,
            });
        }

        string resolverName = "Unknown";
        string resolverAddress = "Unknown";
        string resolverSummary = ReadEffectiveResolverSummary();

        int separatorIndex = resolverSummary.LastIndexOf(" (", StringComparison.Ordinal);
        if (separatorIndex > 0 && resolverSummary.EndsWith(')'))
        {
            resolverName = resolverSummary[..separatorIndex];
            resolverAddress = resolverSummary[(separatorIndex + 2)..^1];
        }
        else
        {
            resolverAddress = resolverSummary;
        }

        string activeInterfaces = string.Join(
            ", ",
            adapters
                .Where(static adapter => string.Equals(adapter.TrafficRole, "Active route", StringComparison.Ordinal))
                .Select(static adapter => adapter.InterfaceName));

        if (string.IsNullOrWhiteSpace(activeInterfaces))
        {
            activeInterfaces = "No active routed adapter detected";
        }

        return new CurrentDnsSnapshot
        {
            ResolverName = resolverName,
            ResolverAddress = resolverAddress,
            ActiveInterfaces = activeInterfaces,
            ResolverNote = BuildResolverNote(),
            Adapters = adapters,
        };
    }

    public static string ReadEffectiveResolverSummary()
    {
        if (OperatingSystem.IsWindows())
        {
            return ReadWindowsResolverSummary();
        }

        if (OperatingSystem.IsLinux())
        {
            return ReadLinuxResolverSummary();
        }

        return "Unknown";
    }

    public static IReadOnlyList<IPAddress> ReadLinuxResolversFromResolvConf()
    {
        const string resolvConfPath = "/etc/resolv.conf";
        if (!File.Exists(resolvConfPath))
        {
            return [];
        }

        var addresses = new List<IPAddress>();

        foreach (string rawLine in File.ReadLines(resolvConfPath))
        {
            string line = rawLine.Trim();
            if (!line.StartsWith("nameserver", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            string[] parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (parts.Length < 2)
            {
                continue;
            }

            if (IPAddress.TryParse(parts[1], out IPAddress? parsedAddress))
            {
                addresses.Add(parsedAddress);
            }
        }

        return addresses;
    }

    public static bool IsWslAutoGeneratedResolvConf()
    {
        if (!PlatformEnvironment.IsWsl())
        {
            return false;
        }

        try
        {
            if (!File.Exists("/etc/resolv.conf"))
            {
                return false;
            }

            string text = File.ReadAllText("/etc/resolv.conf");
            return text.Contains("generated by WSL", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static string ReadWindowsResolverSummary()
    {
        ProcessCommandResult result = ProcessCommand.Run("nslookup.exe", "example.com");

        if (!result.Success || string.IsNullOrWhiteSpace(result.Output))
        {
            return "Unknown";
        }

        string? server = MatchValue(ServerLineRegex, result.Output);
        string? address = MatchValue(AddressLineRegex, result.Output);

        if (!string.IsNullOrWhiteSpace(server) && !string.IsNullOrWhiteSpace(address))
        {
            return $"{server} ({address})";
        }

        return !string.IsNullOrWhiteSpace(address)
            ? address
            : !string.IsNullOrWhiteSpace(server)
                ? server
                : "Unknown";
    }

    private static string ReadLinuxResolverSummary()
    {
        IReadOnlyList<IPAddress> resolvConfServers = ReadLinuxResolversFromResolvConf();
        if (ShouldPreferResolvConfSummary(resolvConfServers))
        {
            return $"resolv.conf ({string.Join(", ", resolvConfServers)})";
        }

        ProcessCommandResult resolvectlResult = ProcessCommand.Run("resolvectl", "status");
        if (resolvectlResult.Success && !string.IsNullOrWhiteSpace(resolvectlResult.Output))
        {
            string? currentDnsServer = MatchValue(ResolvectlCurrentDnsRegex, resolvectlResult.Output);
            string? dnsServers = MatchValue(ResolvectlDnsServersRegex, resolvectlResult.Output);
            string? resolvedAddress = !string.IsNullOrWhiteSpace(currentDnsServer)
                ? currentDnsServer
                : dnsServers;

            if (!string.IsNullOrWhiteSpace(resolvedAddress))
            {
                return $"systemd-resolved ({resolvedAddress})";
            }
        }

        if (resolvConfServers.Count > 0)
        {
            return $"resolv.conf ({string.Join(", ", resolvConfServers)})";
        }

        ProcessCommandResult nslookupResult = ProcessCommand.Run("nslookup", "example.com");
        if (!nslookupResult.Success || string.IsNullOrWhiteSpace(nslookupResult.Output))
        {
            return "Unknown";
        }

        string? server = MatchValue(ServerLineRegex, nslookupResult.Output);
        string? address = MatchValue(AddressLineRegex, nslookupResult.Output);

        if (!string.IsNullOrWhiteSpace(server) && !string.IsNullOrWhiteSpace(address))
        {
            return $"{server} ({address})";
        }

        return !string.IsNullOrWhiteSpace(address)
            ? address
            : !string.IsNullOrWhiteSpace(server)
                ? server
                : "Unknown";
    }

    private static async Task<string> GetDnsModeAsync(
        AddressFamily family,
        string interfaceName,
        string currentServers,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(currentServers) || string.Equals(currentServers, "None", StringComparison.OrdinalIgnoreCase))
        {
            return "None";
        }

        return await Task.Run(
            () => GetDnsMode(family, interfaceName),
            cancellationToken).ConfigureAwait(false);
    }

    private static string GetDnsMode(AddressFamily family, string interfaceName)
    {
        if (OperatingSystem.IsWindows())
        {
            string familyName = family == AddressFamily.InterNetwork ? "ipv4" : "ipv6";
            ProcessCommandResult result = ProcessCommand.Run(
                "netsh.exe",
                "interface",
                familyName,
                "show",
                "dnsservers",
                $"name={interfaceName}");

            return result.Output.Contains("DHCP", StringComparison.OrdinalIgnoreCase)
                ? "DHCP"
                : "Static";
        }

        if (OperatingSystem.IsLinux())
        {
            return GetLinuxDnsMode(family, interfaceName);
        }

        return "Detected";
    }

    private static string GetLinuxDnsMode(AddressFamily family, string interfaceName)
    {
        if (PlatformEnvironment.IsWsl())
        {
            return PlatformEnvironment.WslGeneratesResolvConf()
                ? "Auto (WSL)"
                : "Static";
        }

        if (TryGetNmcliDnsMode(family, interfaceName, out string mode))
        {
            return mode;
        }

        return IsResolvConfManagedAutomatically()
            ? "Auto"
            : "Static";
    }

    private static bool TryGetNmcliDnsMode(AddressFamily family, string interfaceName, out string mode)
    {
        mode = string.Empty;

        if (!ProcessCommand.Exists("nmcli"))
        {
            return false;
        }

        ProcessCommandResult connectionResult = ProcessCommand.Run(
            "nmcli",
            "-g",
            "GENERAL.CONNECTION",
            "device",
            "show",
            interfaceName);

        string connectionName = connectionResult.Output.Trim();
        if (!connectionResult.Success
            || string.IsNullOrWhiteSpace(connectionName)
            || string.Equals(connectionName, "--", StringComparison.Ordinal))
        {
            return false;
        }

        string methodProperty = family == AddressFamily.InterNetwork ? "ipv4.method" : "ipv6.method";
        string ignoreAutoProperty = family == AddressFamily.InterNetwork ? "ipv4.ignore-auto-dns" : "ipv6.ignore-auto-dns";
        string dnsProperty = family == AddressFamily.InterNetwork ? "ipv4.dns" : "ipv6.dns";

        string method = ProcessCommand.Run("nmcli", "-g", methodProperty, "connection", "show", connectionName).Output.Trim();
        string ignoreAuto = ProcessCommand.Run("nmcli", "-g", ignoreAutoProperty, "connection", "show", connectionName).Output.Trim();
        string dnsValue = ProcessCommand.Run("nmcli", "-g", dnsProperty, "connection", "show", connectionName).Output.Trim();

        mode = string.Equals(ignoreAuto, "yes", StringComparison.OrdinalIgnoreCase) || !string.IsNullOrWhiteSpace(dnsValue)
            ? "Static"
            : string.Equals(method, "auto", StringComparison.OrdinalIgnoreCase)
                ? "Auto"
                : string.Equals(method, "manual", StringComparison.OrdinalIgnoreCase)
                    ? "Static"
                    : "Detected";

        return true;
    }

    private static bool IsResolvConfManagedAutomatically()
    {
        const string resolvConfPath = "/etc/resolv.conf";

        try
        {
            var fileInfo = new FileInfo(resolvConfPath);
            string? linkTarget = fileInfo.LinkTarget;
            if (!string.IsNullOrWhiteSpace(linkTarget)
                && (linkTarget.Contains("systemd", StringComparison.OrdinalIgnoreCase)
                    || linkTarget.Contains("resolvconf", StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }

            if (!File.Exists(resolvConfPath))
            {
                return false;
            }

            string text = File.ReadAllText(resolvConfPath);
            return text.Contains("systemd-resolved", StringComparison.OrdinalIgnoreCase)
                || text.Contains("NetworkManager", StringComparison.OrdinalIgnoreCase)
                || text.Contains("generated", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static bool ShouldPreferResolvConfSummary(IReadOnlyList<IPAddress> resolvConfServers)
    {
        if (resolvConfServers.Count == 0)
        {
            return false;
        }

        if (PlatformEnvironment.IsWsl())
        {
            return true;
        }

        return !IsResolvConfManagedAutomatically();
    }

    private static string BuildResolverNote()
    {
        if (OperatingSystem.IsWindows())
        {
            return "Windows can prefer IPv6 DNS when it is present. Browsers with Secure DNS / DoH can also bypass the system resolver entirely.";
        }

        if (PlatformEnvironment.IsWsl())
        {
            return PlatformEnvironment.WslGeneratesResolvConf()
                ? "WSL can regenerate /etc/resolv.conf on restart until /etc/wsl.conf sets generateResolvConf=false. Browsers with Secure DNS / DoH can also bypass the system resolver entirely."
                : "WSL is using a manually managed /etc/resolv.conf. Browsers with Secure DNS / DoH can also bypass the system resolver entirely.";
        }

        if (OperatingSystem.IsLinux())
        {
            return "Linux resolver state can come from NetworkManager, systemd-resolved, or /etc/resolv.conf. Browsers with Secure DNS / DoH can also bypass the system resolver entirely.";
        }

        return $"{PlatformEnvironment.DisplayName} resolver detection is best-effort. Browsers with Secure DNS / DoH can also bypass the system resolver entirely.";
    }

    private static string? MatchValue(Regex regex, string input)
    {
        Match match = regex.Match(input);
        return match.Success ? match.Groups[1].Value.Trim() : null;
    }

    private static string JoinAddresses(IEnumerable<IPAddress> addresses)
    {
        return string.Join(
            ", ",
            addresses
                .Where(static address => !IPAddress.Any.Equals(address) && !IPAddress.IPv6Any.Equals(address))
                .Select(static address => address.ToString()));
    }

    public sealed class CurrentDnsSnapshot
    {
        public required string ResolverName { get; init; }

        public required string ResolverAddress { get; init; }

        public required string ActiveInterfaces { get; init; }

        public required string ResolverNote { get; init; }

        public required IReadOnlyList<CurrentDnsAdapterViewModel> Adapters { get; init; }
    }
}
