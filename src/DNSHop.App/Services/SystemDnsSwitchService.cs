using DNSHop.App.Models;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DNSHop.App.Services;

internal sealed class SystemDnsSwitchService
{
    private const string ApplyCommandName = "--apply-system-dns";
    private const string ResultPathArgumentName = "--result-file";

    public bool CanApply(DnsServerDefinition? server)
        => TryGetUnsupportedReason(server) is null;

    public string? TryGetUnsupportedReason(DnsServerDefinition? server)
    {
        if (server is null)
        {
            return "Select a DNS endpoint first.";
        }

        if (!OperatingSystem.IsWindows())
        {
            return "System DNS switching is currently supported on Windows only.";
        }

        if (server.Protocol != DnsProtocol.UdpTcp)
        {
            return "System DNS switching currently supports classic UDP/TCP DNS endpoints only.";
        }

        if (server.Port != 53)
        {
            return "System DNS switching currently supports classic DNS endpoints on port 53 only.";
        }

        if (!IPAddress.TryParse(server.AddressOrHost, out var parsedAddress))
        {
            return "The selected DNS endpoint does not expose a direct IP address.";
        }

        if (parsedAddress.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))
        {
            return "Only IPv4 and IPv6 system DNS endpoints can be applied.";
        }

        return null;
    }

    public async Task<SystemDnsSwitchResult> ApplyAsync(DnsServerDefinition server, CancellationToken cancellationToken)
    {
        if (TryGetUnsupportedReason(server) is { } reason)
        {
            return SystemDnsSwitchResult.Failure(reason);
        }

        string? executablePath = GetCurrentExecutablePath();
        if (string.IsNullOrWhiteSpace(executablePath) || !File.Exists(executablePath))
        {
            return SystemDnsSwitchResult.Failure("Unable to locate the DNS Hop executable for elevation.");
        }

        string resultPath = Path.Combine(
            Path.GetTempPath(),
            $"dnshop-system-dns-{Guid.NewGuid():N}.result");

        try
        {
            string arguments =
                $"{ApplyCommandName} {QuoteArgument(server.AddressOrHost)} {ResultPathArgumentName} {QuoteArgument(resultPath)}";

            var startInfo = new ProcessStartInfo
            {
                FileName = executablePath,
                Arguments = arguments,
                UseShellExecute = true,
                Verb = "runas",
                WindowStyle = ProcessWindowStyle.Hidden,
            };

            using var process = Process.Start(startInfo);

            if (process is null)
            {
                return SystemDnsSwitchResult.Failure("Unable to start the Windows DNS switch command.");
            }

            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);

            if (File.Exists(resultPath))
            {
                return await ReadResultAsync(resultPath, cancellationToken).ConfigureAwait(false);
            }

            return process.ExitCode == 0
                ? SystemDnsSwitchResult.Succeeded($"Applied {server.AddressOrHost}.")
                : SystemDnsSwitchResult.Failure("Windows rejected the DNS change.");
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            return SystemDnsSwitchResult.Failure("DNS switch canceled at the Windows elevation prompt.");
        }
        catch (OperationCanceledException)
        {
            return SystemDnsSwitchResult.Failure("DNS switch canceled.");
        }
        catch (Exception ex)
        {
            return SystemDnsSwitchResult.Failure($"DNS switch failed: {ex.Message}");
        }
        finally
        {
            TryDelete(resultPath);
        }
    }

    public static bool TryHandleCommandLine(string[] args, out int exitCode)
    {
        exitCode = 0;

        if (args.Length == 0 || !string.Equals(args[0], ApplyCommandName, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        string? dnsServer = null;
        string? resultPath = null;

        for (int index = 1; index < args.Length; index++)
        {
            string current = args[index];

            if (dnsServer is null && !current.StartsWith("--", StringComparison.Ordinal))
            {
                dnsServer = current;
                continue;
            }

            if (string.Equals(current, ResultPathArgumentName, StringComparison.OrdinalIgnoreCase)
                && index + 1 < args.Length)
            {
                resultPath = args[++index];
            }
        }

        var result = ApplyInElevatedProcess(dnsServer, resultPath);
        exitCode = result.Success ? 0 : 1;
        return true;
    }

    private static SystemDnsSwitchResult ApplyInElevatedProcess(string? dnsServer, string? resultPath)
    {
        SystemDnsSwitchResult result;

        try
        {
            result = ApplyToWindowsAdapters(dnsServer);
        }
        catch (Exception ex)
        {
            result = SystemDnsSwitchResult.Failure($"DNS switch failed: {ex.Message}");
        }

        try
        {
            if (!string.IsNullOrWhiteSpace(resultPath))
            {
                WriteResult(resultPath, result);
            }
        }
        catch
        {
            // The elevated helper should still return an exit code even if the temp file write fails.
        }

        return result;
    }

    private static SystemDnsSwitchResult ApplyToWindowsAdapters(string? dnsServer)
    {
        if (string.IsNullOrWhiteSpace(dnsServer) || !IPAddress.TryParse(dnsServer, out var parsedAddress))
        {
            return SystemDnsSwitchResult.Failure("The selected DNS endpoint is not a valid IP address.");
        }

        if (parsedAddress.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))
        {
            return SystemDnsSwitchResult.Failure("Only IPv4 and IPv6 DNS servers can be applied.");
        }

        string[] targets = FindTargetInterfaces(parsedAddress.AddressFamily).ToArray();

        if (targets.Length == 0)
        {
            return SystemDnsSwitchResult.Failure("No active network adapters were found.");
        }

        foreach (string target in targets)
        {
            if (parsedAddress.AddressFamily == AddressFamily.InterNetwork)
            {
                TryClearDnsFamily("ipv6", target);

                var setIpv4Result = RunCommand(
                    "netsh.exe",
                    $"interface ipv4 set dnsservers name={QuoteArgument(target)} source=static address={dnsServer} register=primary validate=no");

                if (!setIpv4Result.Success)
                {
                    return SystemDnsSwitchResult.Failure(
                        $"Failed to set IPv4 DNS on {target}: {setIpv4Result.Message}");
                }

                var verifyIpv4Result = RunCommand(
                    "netsh.exe",
                    $"interface ipv4 show dnsservers name={QuoteArgument(target)}");

                if (!verifyIpv4Result.Output.Contains(dnsServer, StringComparison.OrdinalIgnoreCase))
                {
                    return SystemDnsSwitchResult.Failure(
                        $"Windows did not confirm {dnsServer} on {target}.");
                }
            }
            else
            {
                TryClearDnsFamily("ipv4", target);

                var setIpv6Result = RunCommand(
                    "netsh.exe",
                    $"interface ipv6 set dnsservers name={QuoteArgument(target)} source=static address={dnsServer} validate=no");

                if (!setIpv6Result.Success)
                {
                    return SystemDnsSwitchResult.Failure(
                        $"Failed to set IPv6 DNS on {target}: {setIpv6Result.Message}");
                }

                var verifyIpv6Result = RunCommand(
                    "netsh.exe",
                    $"interface ipv6 show dnsservers name={QuoteArgument(target)}");

                if (!verifyIpv6Result.Output.Contains(dnsServer, StringComparison.OrdinalIgnoreCase))
                {
                    return SystemDnsSwitchResult.Failure(
                        $"Windows did not confirm {dnsServer} on {target}.");
                }
            }
        }

        RunCommand("ipconfig.exe", "/flushdns");

        string effectiveResolver = CurrentDnsStatusService.ReadEffectiveResolverSummary();
        string targetList = string.Join(", ", targets);

        return SystemDnsSwitchResult.Succeeded(
            $"Applied {dnsServer} to {targetList}. Current Windows resolver: {effectiveResolver}.");
    }

    private static string[] FindTargetInterfaces(AddressFamily selectedFamily)
    {
        return NetworkInterface.GetAllNetworkInterfaces()
            .Where(static networkInterface =>
                networkInterface.OperationalStatus == OperationalStatus.Up
                && networkInterface.NetworkInterfaceType is not NetworkInterfaceType.Loopback
                and not NetworkInterfaceType.Tunnel)
            .Where(networkInterface => HasUsableGateway(networkInterface))
            .Where(networkInterface => HasAddressFamily(networkInterface, selectedFamily))
            .Select(static networkInterface => networkInterface.Name)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static bool HasUsableGateway(NetworkInterface networkInterface)
    {
        return networkInterface
            .GetIPProperties()
            .GatewayAddresses
            .Any(static gateway => gateway.Address is not null
                && !IPAddress.Any.Equals(gateway.Address)
                && !IPAddress.IPv6Any.Equals(gateway.Address));
    }

    private static bool HasAddressFamily(NetworkInterface networkInterface, AddressFamily selectedFamily)
    {
        return networkInterface
            .GetIPProperties()
            .UnicastAddresses
            .Any(unicast => unicast.Address.AddressFamily == selectedFamily
                && !IPAddress.IsLoopback(unicast.Address));
    }

    private static void TryClearDnsFamily(string family, string interfaceName)
    {
        var clearResult = RunCommand(
            "netsh.exe",
            $"interface {family} set dnsservers name={QuoteArgument(interfaceName)} source=static address=none validate=no");

        if (clearResult.Success)
        {
            return;
        }

        RunCommand(
            "netsh.exe",
            $"interface {family} delete dnsservers name={QuoteArgument(interfaceName)} all validate=no");
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

        string message = string.IsNullOrWhiteSpace(stderr) ? stdout : stderr;

        return new CommandResult(
            process.ExitCode == 0,
            stdout,
            NormalizeMessage(message));
    }

    private static async Task<SystemDnsSwitchResult> ReadResultAsync(string resultPath, CancellationToken cancellationToken)
    {
        string[] lines = await File.ReadAllLinesAsync(resultPath, cancellationToken).ConfigureAwait(false);

        if (lines.Length == 0)
        {
            return SystemDnsSwitchResult.Failure("Windows returned an empty DNS switch response.");
        }

        bool success = string.Equals(lines[0], "success", StringComparison.OrdinalIgnoreCase);
        string message = lines.Length > 1 && !string.IsNullOrWhiteSpace(lines[1])
            ? lines[1]
            : success
                ? "DNS switch applied."
                : "Windows rejected the DNS change.";

        return success
            ? SystemDnsSwitchResult.Succeeded(message)
            : SystemDnsSwitchResult.Failure(message);
    }

    private static void WriteResult(string resultPath, SystemDnsSwitchResult result)
    {
        string? directory = Path.GetDirectoryName(resultPath);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        File.WriteAllLines(
            resultPath,
            [
                result.Success ? "success" : "failure",
                result.Message,
            ],
            Encoding.UTF8);
    }

    private static string? GetCurrentExecutablePath()
        => Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule?.FileName;

    private static string QuoteArgument(string value)
        => "\"" + value.Replace("\"", "\\\"", StringComparison.Ordinal) + "\"";

    private static string NormalizeMessage(string? rawMessage)
    {
        if (string.IsNullOrWhiteSpace(rawMessage))
        {
            return "The command finished without output.";
        }

        return string.Join(
            " ",
            rawMessage
                .Split([Environment.NewLine, "\r", "\n"], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
            // Best effort only for temp response files.
        }
    }

    private readonly record struct CommandResult(bool Success, string Output, string Message);
}

internal sealed record SystemDnsSwitchResult(bool Success, string Message)
{
    public static SystemDnsSwitchResult Failure(string message) => new(false, message);

    public static SystemDnsSwitchResult Succeeded(string message) => new(true, message);
}
