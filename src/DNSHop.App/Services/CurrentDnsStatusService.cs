using DNSHop.App.ViewModels;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace DNSHop.App.Services;

internal sealed class CurrentDnsStatusService
{
    private static readonly Regex ServerLineRegex = new(@"^\s*Server:\s*(.+)$", RegexOptions.Multiline | RegexOptions.Compiled);
    private static readonly Regex AddressLineRegex = new(@"^\s*Address:\s*(.+)$", RegexOptions.Multiline | RegexOptions.Compiled);

    public async Task<CurrentDnsSnapshot> GetSnapshotAsync(CancellationToken cancellationToken)
    {
        var adapters = new List<CurrentDnsAdapterViewModel>();

        foreach (var networkInterface in NetworkInterface.GetAllNetworkInterfaces()
                     .OrderByDescending(static networkInterface => networkInterface.OperationalStatus == OperationalStatus.Up)
                     .ThenBy(static networkInterface => networkInterface.Name, StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();

            var properties = networkInterface.GetIPProperties();
            string gateways = JoinAddresses(properties.GatewayAddresses.Select(static gateway => gateway.Address));
            string dnsServersV4 = JoinAddresses(properties.DnsAddresses.Where(static address => address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork));
            string dnsServersV6 = JoinAddresses(properties.DnsAddresses.Where(static address => address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6));

            string ipv4Mode = await GetDnsModeAsync(
                "ipv4",
                networkInterface.Name,
                dnsServersV4,
                cancellationToken).ConfigureAwait(false);

            string ipv6Mode = await GetDnsModeAsync(
                "ipv6",
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
            ResolverNote = "Windows can prefer IPv6 DNS when it is present. Browsers with Secure DNS / DoH can also bypass the system resolver entirely.",
            Adapters = adapters,
        };
    }

    public static string ReadEffectiveResolverSummary()
    {
        var result = RunCommand("nslookup.exe", "example.com");

        if (!result.Success || string.IsNullOrWhiteSpace(result.Output))
        {
            return "Unknown";
        }

        string? server = ServerLineRegex.Match(result.Output) is { Success: true } serverMatch
            ? serverMatch.Groups[1].Value.Trim()
            : null;

        string? address = AddressLineRegex.Match(result.Output) is { Success: true } addressMatch
            ? addressMatch.Groups[1].Value.Trim()
            : null;

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
        string family,
        string interfaceName,
        string currentServers,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(currentServers) || string.Equals(currentServers, "None", StringComparison.OrdinalIgnoreCase))
        {
            return "None";
        }

        var result = await Task.Run(
            () => RunCommand("netsh.exe", $"interface {family} show dnsservers name=\"{interfaceName}\""),
            cancellationToken).ConfigureAwait(false);

        if (result.Output.Contains("DHCP", StringComparison.OrdinalIgnoreCase))
        {
            return "DHCP";
        }

        return "Static";
    }

    private static string JoinAddresses(IEnumerable<IPAddress> addresses)
    {
        return string.Join(
            ", ",
            addresses
                .Where(static address => !IPAddress.Any.Equals(address) && !IPAddress.IPv6Any.Equals(address))
                .Select(static address => address.ToString()));
    }

    private static CommandResult RunCommand(string fileName, string arguments)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = arguments,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };

        using var process = new Process { StartInfo = startInfo };
        process.Start();

        string stdout = process.StandardOutput.ReadToEnd();
        string stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();

        return new CommandResult(
            process.ExitCode == 0,
            string.IsNullOrWhiteSpace(stdout) ? stderr : stdout);
    }

    public sealed class CurrentDnsSnapshot
    {
        public required string ResolverName { get; init; }

        public required string ResolverAddress { get; init; }

        public required string ActiveInterfaces { get; init; }

        public required string ResolverNote { get; init; }

        public required IReadOnlyList<CurrentDnsAdapterViewModel> Adapters { get; init; }
    }

    private readonly record struct CommandResult(bool Success, string Output);
}
