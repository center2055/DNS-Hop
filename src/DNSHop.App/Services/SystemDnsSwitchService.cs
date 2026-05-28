using DNSHop.App.Models;
using System;
using System.Collections.Generic;
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
    private const string ApplyMultiCommandName = "--apply-system-dns-multi";
    private const string ResultPathArgumentName = "--result-file";
    private const string Ipv4ListArgumentName = "--ipv4";
    private const string Ipv6ListArgumentName = "--ipv6";
    private const string LinuxResolvConfPath = "/etc/resolv.conf";
    private const string LinuxResolvConfBackupPath = "/etc/resolv.conf.dnshop.bak";

    public bool CanApply(DnsServerDefinition? server)
        => TryGetUnsupportedReason(server) is null;

    public string? TryGetUnsupportedReason(DnsServerDefinition? server)
    {
        if (server is null)
        {
            return "Select a DNS endpoint first.";
        }

        if (!OperatingSystem.IsWindows() && !OperatingSystem.IsLinux())
        {
            return "System DNS switching currently supports Windows and Linux only.";
        }

        if (server.Protocol != DnsProtocol.UdpTcp)
        {
            return "System DNS switching currently supports classic UDP/TCP DNS endpoints only.";
        }

        if (server.Port != 53)
        {
            return "System DNS switching currently supports classic DNS endpoints on port 53 only.";
        }

        if (!IPAddress.TryParse(server.AddressOrHost, out IPAddress? parsedAddress))
        {
            return "The selected DNS endpoint does not expose a direct IP address.";
        }

        if (parsedAddress.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))
        {
            return "Only IPv4 and IPv6 system DNS endpoints can be applied.";
        }

        return null;
    }

    public async Task<SystemDnsSwitchResult> ApplyProfileAsync(DnsProfile profile, CancellationToken cancellationToken)
    {
        if (profile is null)
        {
            return SystemDnsSwitchResult.Failure("No profile supplied.");
        }

        var ipv4 = new List<string>(2);
        if (!string.IsNullOrWhiteSpace(profile.PreferredIPv4) && IPAddress.TryParse(profile.PreferredIPv4, out _))
        {
            ipv4.Add(profile.PreferredIPv4!.Trim());
        }
        if (!string.IsNullOrWhiteSpace(profile.AlternateIPv4) && IPAddress.TryParse(profile.AlternateIPv4, out _))
        {
            ipv4.Add(profile.AlternateIPv4!.Trim());
        }

        var ipv6 = new List<string>(2);
        if (!string.IsNullOrWhiteSpace(profile.PreferredIPv6) && IPAddress.TryParse(profile.PreferredIPv6, out _))
        {
            ipv6.Add(profile.PreferredIPv6!.Trim());
        }
        if (!string.IsNullOrWhiteSpace(profile.AlternateIPv6) && IPAddress.TryParse(profile.AlternateIPv6, out _))
        {
            ipv6.Add(profile.AlternateIPv6!.Trim());
        }

        if (ipv4.Count == 0 && ipv6.Count == 0)
        {
            return SystemDnsSwitchResult.Failure("Profile has no valid IPv4 or IPv6 endpoint.");
        }

        AppDiagnostics.WriteInfo("SystemDns", $"Applying profile '{profile.Name}': v4=[{string.Join(',', ipv4)}] v6=[{string.Join(',', ipv6)}].");

        if (OperatingSystem.IsWindows())
        {
            return await ApplyMultiOnWindowsAsync(ipv4, ipv6, cancellationToken).ConfigureAwait(false);
        }

        if (OperatingSystem.IsLinux() && ipv4.Count > 0)
        {
            // Linux profile apply currently lands the preferred IPv4 via the existing single-IP path;
            // multi-server Linux apply is tracked as a follow-up.
            var legacyServer = DnsServerDefinition.CreateUdpTcp(ipv4[0], profile.Name);
            return await ApplyAsync(legacyServer, cancellationToken).ConfigureAwait(false);
        }

        return SystemDnsSwitchResult.Failure("Profile apply is supported on Windows and Linux only.");
    }

    public async Task<SystemDnsSwitchResult> ApplyAsync(DnsServerDefinition server, CancellationToken cancellationToken)
    {
        if (TryGetUnsupportedReason(server) is { } reason)
        {
            return SystemDnsSwitchResult.Failure(reason);
        }

        AppDiagnostics.WriteInfo("SystemDns", $"Applying system DNS endpoint {server.EndpointDisplay}.");

        SystemDnsSwitchResult result = OperatingSystem.IsWindows()
            ? await ApplyOnWindowsAsync(server, cancellationToken).ConfigureAwait(false)
            : await ApplyOnLinuxAsync(server, cancellationToken).ConfigureAwait(false);

        if (result.Success)
        {
            AppDiagnostics.WriteInfo("SystemDns", result.Message);
        }
        else
        {
            AppDiagnostics.WriteWarning("SystemDns", result.Message);
        }

        return result;
    }

    public static bool TryHandleCommandLine(string[] args, out int exitCode)
    {
        exitCode = 0;

        if (args.Length == 0)
        {
            return false;
        }

        if (string.Equals(args[0], ApplyMultiCommandName, StringComparison.OrdinalIgnoreCase))
        {
            string? resultPath = null;
            string[] ipv4 = Array.Empty<string>();
            string[] ipv6 = Array.Empty<string>();

            for (int index = 1; index < args.Length; index++)
            {
                string current = args[index];
                if (string.Equals(current, ResultPathArgumentName, StringComparison.OrdinalIgnoreCase) && index + 1 < args.Length)
                {
                    resultPath = args[++index];
                }
                else if (string.Equals(current, Ipv4ListArgumentName, StringComparison.OrdinalIgnoreCase) && index + 1 < args.Length)
                {
                    ipv4 = SplitIpList(args[++index]);
                }
                else if (string.Equals(current, Ipv6ListArgumentName, StringComparison.OrdinalIgnoreCase) && index + 1 < args.Length)
                {
                    ipv6 = SplitIpList(args[++index]);
                }
            }

            SystemDnsSwitchResult multiResult = ApplyMultiInElevatedProcess(ipv4, ipv6, resultPath);
            exitCode = multiResult.Success ? 0 : 1;
            return true;
        }

        if (!string.Equals(args[0], ApplyCommandName, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        string? dnsServer = null;
        string? singleResultPath = null;

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
                singleResultPath = args[++index];
            }
        }

        SystemDnsSwitchResult result = ApplyInElevatedProcess(dnsServer, singleResultPath);
        exitCode = result.Success ? 0 : 1;
        return true;
    }

    private static string[] SplitIpList(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return Array.Empty<string>();
        }
        return raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    private async Task<SystemDnsSwitchResult> ApplyMultiOnWindowsAsync(
        IReadOnlyList<string> ipv4,
        IReadOnlyList<string> ipv6,
        CancellationToken cancellationToken)
    {
        string resultPath = BuildResultPath();

        try
        {
            ProcessStartInfo? startInfo = TryCreateWindowsMultiElevationStartInfo(ipv4, ipv6, resultPath);
            if (startInfo is null)
            {
                return SystemDnsSwitchResult.Failure("Unable to locate the DNS Hop executable for elevation.");
            }

            using Process? process = Process.Start(startInfo);
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
                ? SystemDnsSwitchResult.Succeeded("Profile applied.")
                : SystemDnsSwitchResult.Failure("Windows rejected the DNS profile change.");
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            AppDiagnostics.WriteWarning("SystemDns", "Profile apply canceled at elevation prompt.");
            return SystemDnsSwitchResult.Failure("Profile apply canceled at the Windows elevation prompt.");
        }
        catch (OperationCanceledException)
        {
            return SystemDnsSwitchResult.Failure("Profile apply canceled.");
        }
        catch (Exception ex)
        {
            AppDiagnostics.WriteError("SystemDns", "Windows profile apply failed.", ex);
            return SystemDnsSwitchResult.Failure($"Profile apply failed: {ex.Message}");
        }
        finally
        {
            TryDelete(resultPath);
        }
    }

    private async Task<SystemDnsSwitchResult> ApplyOnWindowsAsync(DnsServerDefinition server, CancellationToken cancellationToken)
    {
        string resultPath = BuildResultPath();

        try
        {
            ProcessStartInfo? startInfo = TryCreateWindowsElevationStartInfo(server.AddressOrHost, resultPath);
            if (startInfo is null)
            {
                return SystemDnsSwitchResult.Failure("Unable to locate the DNS Hop executable for elevation.");
            }

            using Process? process = Process.Start(startInfo);
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
            AppDiagnostics.WriteWarning("SystemDns", "Windows DNS switch canceled at elevation prompt.");
            return SystemDnsSwitchResult.Failure("DNS switch canceled at the Windows elevation prompt.");
        }
        catch (OperationCanceledException)
        {
            AppDiagnostics.WriteWarning("SystemDns", "Windows DNS switch canceled.");
            return SystemDnsSwitchResult.Failure("DNS switch canceled.");
        }
        catch (Exception ex)
        {
            AppDiagnostics.WriteError("SystemDns", "Windows DNS switch failed.", ex);
            return SystemDnsSwitchResult.Failure($"DNS switch failed: {ex.Message}");
        }
        finally
        {
            TryDelete(resultPath);
        }
    }

    private async Task<SystemDnsSwitchResult> ApplyOnLinuxAsync(DnsServerDefinition server, CancellationToken cancellationToken)
    {
        string resultPath = BuildResultPath();

        try
        {
            ProcessStartInfo? startInfo = TryCreateLinuxElevationStartInfo(server.AddressOrHost, resultPath);
            if (startInfo is null)
            {
                return SystemDnsSwitchResult.Failure(
                    "No supported Linux elevation tool was found. Install sudo or pkexec, or start DNS Hop as root.");
            }

            using Process? process = Process.Start(startInfo);
            if (process is null)
            {
                return SystemDnsSwitchResult.Failure("Unable to start the Linux DNS switch command.");
            }

            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);

            if (File.Exists(resultPath))
            {
                return await ReadResultAsync(resultPath, cancellationToken).ConfigureAwait(false);
            }

            return process.ExitCode == 0
                ? SystemDnsSwitchResult.Succeeded($"Applied {server.AddressOrHost}.")
                : PlatformEnvironment.IsWsl()
                    ? SystemDnsSwitchResult.Failure("Linux rejected the DNS change. In WSL, start DNS Hop from a terminal so sudo can prompt for your password.")
                    : SystemDnsSwitchResult.Failure("Linux rejected the DNS change. If no desktop privilege prompt is available, start DNS Hop from a terminal or run it as root.");
        }
        catch (OperationCanceledException)
        {
            AppDiagnostics.WriteWarning("SystemDns", "Linux DNS switch canceled.");
            return SystemDnsSwitchResult.Failure("DNS switch canceled.");
        }
        catch (Exception ex)
        {
            AppDiagnostics.WriteError("SystemDns", "Linux DNS switch failed.", ex);
            return SystemDnsSwitchResult.Failure($"DNS switch failed: {ex.Message}");
        }
        finally
        {
            TryDelete(resultPath);
        }
    }

    private static string BuildResultPath()
        => Path.Combine(
            Path.GetTempPath(),
            $"dnshop-system-dns-{Guid.NewGuid():N}.result");

    private static ProcessStartInfo? TryCreateWindowsMultiElevationStartInfo(
        IReadOnlyList<string> ipv4,
        IReadOnlyList<string> ipv6,
        string resultPath)
    {
        var args = new List<string>
        {
            ApplyMultiCommandName,
            ResultPathArgumentName,
            resultPath,
        };

        if (ipv4.Count > 0)
        {
            args.Add(Ipv4ListArgumentName);
            args.Add(string.Join(',', ipv4));
        }
        if (ipv6.Count > 0)
        {
            args.Add(Ipv6ListArgumentName);
            args.Add(string.Join(',', ipv6));
        }

        SelfInvocationCommand? invocation = ProcessCommand.TryCreateSelfInvocation(args);
        if (invocation is null)
        {
            return null;
        }

        return new ProcessStartInfo
        {
            FileName = invocation.FileName,
            Arguments = string.Join(" ", invocation.Arguments.Select(QuoteArgument)),
            UseShellExecute = true,
            Verb = "runas",
            WindowStyle = ProcessWindowStyle.Hidden,
            WorkingDirectory = Environment.CurrentDirectory,
        };
    }

    private static ProcessStartInfo? TryCreateWindowsElevationStartInfo(string dnsServer, string resultPath)
    {
        SelfInvocationCommand? invocation = ProcessCommand.TryCreateSelfInvocation(
        [
            ApplyCommandName,
            dnsServer,
            ResultPathArgumentName,
            resultPath,
        ]);

        if (invocation is null)
        {
            return null;
        }

        return new ProcessStartInfo
        {
            FileName = invocation.FileName,
            Arguments = string.Join(" ", invocation.Arguments.Select(QuoteArgument)),
            UseShellExecute = true,
            Verb = "runas",
            WindowStyle = ProcessWindowStyle.Hidden,
            WorkingDirectory = Environment.CurrentDirectory,
        };
    }

    private static ProcessStartInfo? TryCreateLinuxElevationStartInfo(string dnsServer, string resultPath)
    {
        SelfInvocationCommand? invocation = ProcessCommand.TryCreateSelfInvocation(
        [
            ApplyCommandName,
            dnsServer,
            ResultPathArgumentName,
            resultPath,
        ]);

        if (invocation is null)
        {
            return null;
        }

        if (IsRunningAsRoot())
        {
            return CreateProcessStartInfo(invocation.FileName, invocation.Arguments);
        }

        if (PlatformEnvironment.IsWsl() && ProcessCommand.Exists("sudo"))
        {
            return CreateLinuxWrapperStartInfo("sudo", invocation);
        }

        if (ProcessCommand.Exists("pkexec"))
        {
            return CreateLinuxWrapperStartInfo("pkexec", invocation);
        }

        if (ProcessCommand.Exists("sudo"))
        {
            return CreateLinuxWrapperStartInfo("sudo", invocation);
        }

        if (ProcessCommand.Exists("doas"))
        {
            return CreateLinuxWrapperStartInfo("doas", invocation);
        }

        return null;
    }

    private static ProcessStartInfo CreateLinuxWrapperStartInfo(string wrapperCommand, SelfInvocationCommand invocation)
    {
        IEnumerable<string> arguments = wrapperCommand is "sudo" or "doas"
            ? new[] { "--", invocation.FileName }.Concat(invocation.Arguments)
            : new[] { invocation.FileName }.Concat(invocation.Arguments);

        return CreateProcessStartInfo(wrapperCommand, arguments);
    }

    private static ProcessStartInfo CreateProcessStartInfo(string fileName, IEnumerable<string> arguments)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = fileName,
            UseShellExecute = false,
            RedirectStandardInput = false,
            RedirectStandardOutput = false,
            RedirectStandardError = false,
            CreateNoWindow = true,
            WorkingDirectory = Environment.CurrentDirectory,
        };

        foreach (string argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        return startInfo;
    }

    private static bool IsRunningAsRoot()
    {
        ProcessCommandResult result = ProcessCommand.Run("id", "-u");
        return result.Success && string.Equals(result.Output.Trim(), "0", StringComparison.Ordinal);
    }

    private static SystemDnsSwitchResult ApplyMultiInElevatedProcess(string[] ipv4, string[] ipv6, string? resultPath)
    {
        SystemDnsSwitchResult result;

        try
        {
            result = OperatingSystem.IsWindows()
                ? ApplyMultiToWindowsAdapters(ipv4, ipv6)
                : SystemDnsSwitchResult.Failure("Multi-server DNS apply is currently Windows-only.");
        }
        catch (Exception ex)
        {
            AppDiagnostics.WriteError("SystemDns", "Multi-server elevated helper failed.", ex);
            result = SystemDnsSwitchResult.Failure($"Profile apply failed: {ex.Message}");
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
        }

        if (result.Success)
        {
            AppDiagnostics.WriteInfo(
                "SystemDns",
                $"Elevated multi helper applied v4=[{string.Join(',', ipv4)}] v6=[{string.Join(',', ipv6)}].");
        }
        else
        {
            AppDiagnostics.WriteWarning(
                "SystemDns",
                $"Elevated multi helper failed for v4=[{string.Join(',', ipv4)}] v6=[{string.Join(',', ipv6)}]: {result.Message}");
        }

        return result;
    }

    private static SystemDnsSwitchResult ApplyMultiToWindowsAdapters(string[] ipv4, string[] ipv6)
    {
        foreach (var ip in ipv4)
        {
            if (!IPAddress.TryParse(ip, out var parsed) || parsed.AddressFamily != AddressFamily.InterNetwork)
            {
                return SystemDnsSwitchResult.Failure($"Invalid IPv4 entry: {ip}");
            }
        }
        foreach (var ip in ipv6)
        {
            if (!IPAddress.TryParse(ip, out var parsed) || parsed.AddressFamily != AddressFamily.InterNetworkV6)
            {
                return SystemDnsSwitchResult.Failure($"Invalid IPv6 entry: {ip}");
            }
        }

        var v4Targets = ipv4.Length > 0
            ? FindTargetInterfaces(AddressFamily.InterNetwork)
            : Array.Empty<string>();
        var v6Targets = ipv6.Length > 0
            ? FindTargetInterfaces(AddressFamily.InterNetworkV6)
            : Array.Empty<string>();
        string[] allTargets = v4Targets.Concat(v6Targets).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();

        if (allTargets.Length == 0)
        {
            return SystemDnsSwitchResult.Failure("No active network adapters were found.");
        }

        foreach (string target in allTargets)
        {
            if (ipv4.Length > 0 && Array.Exists(v4Targets, t => string.Equals(t, target, StringComparison.OrdinalIgnoreCase)))
            {
                var setResult = ProcessCommand.Run("netsh.exe", "interface", "ipv4", "set", "dnsservers",
                    $"name={target}", "source=static", $"address={ipv4[0]}", "register=primary", "validate=no");
                if (!setResult.Success)
                {
                    return SystemDnsSwitchResult.Failure($"Failed to set IPv4 DNS on {target}: {setResult.CombinedOutput}");
                }

                for (int i = 1; i < ipv4.Length; i++)
                {
                    var addResult = ProcessCommand.Run("netsh.exe", "interface", "ipv4", "add", "dnsservers",
                        $"name={target}", $"address={ipv4[i]}", $"index={i + 1}", "validate=no");
                    if (!addResult.Success)
                    {
                        return SystemDnsSwitchResult.Failure($"Failed to add IPv4 DNS {ipv4[i]} on {target}: {addResult.CombinedOutput}");
                    }
                }
            }

            if (ipv6.Length > 0 && Array.Exists(v6Targets, t => string.Equals(t, target, StringComparison.OrdinalIgnoreCase)))
            {
                var setResult = ProcessCommand.Run("netsh.exe", "interface", "ipv6", "set", "dnsservers",
                    $"name={target}", "source=static", $"address={ipv6[0]}", "validate=no");
                if (!setResult.Success)
                {
                    return SystemDnsSwitchResult.Failure($"Failed to set IPv6 DNS on {target}: {setResult.CombinedOutput}");
                }

                for (int i = 1; i < ipv6.Length; i++)
                {
                    var addResult = ProcessCommand.Run("netsh.exe", "interface", "ipv6", "add", "dnsservers",
                        $"name={target}", $"address={ipv6[i]}", $"index={i + 1}", "validate=no");
                    if (!addResult.Success)
                    {
                        return SystemDnsSwitchResult.Failure($"Failed to add IPv6 DNS {ipv6[i]} on {target}: {addResult.CombinedOutput}");
                    }
                }
            }
        }

        ProcessCommand.Run("ipconfig.exe", "/flushdns");

        string effectiveResolver = CurrentDnsStatusService.ReadEffectiveResolverSummary();
        return SystemDnsSwitchResult.Succeeded(
            $"Applied profile to {string.Join(", ", allTargets)}. Current Windows resolver: {effectiveResolver}.");
    }

    private static SystemDnsSwitchResult ApplyInElevatedProcess(string? dnsServer, string? resultPath)
    {
        SystemDnsSwitchResult result;

        try
        {
            result = OperatingSystem.IsWindows()
                ? ApplyToWindowsAdapters(dnsServer)
                : OperatingSystem.IsLinux()
                    ? ApplyToLinux(dnsServer)
                    : SystemDnsSwitchResult.Failure("System DNS switching is not supported on this platform.");
        }
        catch (Exception ex)
        {
            AppDiagnostics.WriteError("SystemDns", "Elevated DNS helper failed.", ex);
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

        if (result.Success)
        {
            AppDiagnostics.WriteInfo("SystemDns", $"Elevated helper applied DNS server '{dnsServer}'.");
        }
        else
        {
            AppDiagnostics.WriteWarning("SystemDns", $"Elevated helper failed for DNS server '{dnsServer}': {result.Message}");
        }

        return result;
    }

    private static SystemDnsSwitchResult ApplyToWindowsAdapters(string? dnsServer)
    {
        if (string.IsNullOrWhiteSpace(dnsServer) || !IPAddress.TryParse(dnsServer, out IPAddress? parsedAddress))
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

                ProcessCommandResult setIpv4Result = ProcessCommand.Run(
                    "netsh.exe",
                    "interface",
                    "ipv4",
                    "set",
                    "dnsservers",
                    $"name={target}",
                    "source=static",
                    $"address={dnsServer}",
                    "register=primary",
                    "validate=no");

                if (!setIpv4Result.Success)
                {
                    return SystemDnsSwitchResult.Failure(
                        $"Failed to set IPv4 DNS on {target}: {setIpv4Result.CombinedOutput}");
                }

                ProcessCommandResult verifyIpv4Result = ProcessCommand.Run(
                    "netsh.exe",
                    "interface",
                    "ipv4",
                    "show",
                    "dnsservers",
                    $"name={target}");

                if (!verifyIpv4Result.Output.Contains(dnsServer, StringComparison.OrdinalIgnoreCase))
                {
                    return SystemDnsSwitchResult.Failure(
                        $"Windows did not confirm {dnsServer} on {target}.");
                }
            }
            else
            {
                TryClearDnsFamily("ipv4", target);

                ProcessCommandResult setIpv6Result = ProcessCommand.Run(
                    "netsh.exe",
                    "interface",
                    "ipv6",
                    "set",
                    "dnsservers",
                    $"name={target}",
                    "source=static",
                    $"address={dnsServer}",
                    "validate=no");

                if (!setIpv6Result.Success)
                {
                    return SystemDnsSwitchResult.Failure(
                        $"Failed to set IPv6 DNS on {target}: {setIpv6Result.CombinedOutput}");
                }

                ProcessCommandResult verifyIpv6Result = ProcessCommand.Run(
                    "netsh.exe",
                    "interface",
                    "ipv6",
                    "show",
                    "dnsservers",
                    $"name={target}");

                if (!verifyIpv6Result.Output.Contains(dnsServer, StringComparison.OrdinalIgnoreCase))
                {
                    return SystemDnsSwitchResult.Failure(
                        $"Windows did not confirm {dnsServer} on {target}.");
                }
            }
        }

        ProcessCommand.Run("ipconfig.exe", "/flushdns");

        string effectiveResolver = CurrentDnsStatusService.ReadEffectiveResolverSummary();
        string targetList = string.Join(", ", targets);

        return SystemDnsSwitchResult.Succeeded(
            $"Applied {dnsServer} to {targetList}. Current Windows resolver: {effectiveResolver}.");
    }

    private static SystemDnsSwitchResult ApplyToLinux(string? dnsServer)
    {
        if (string.IsNullOrWhiteSpace(dnsServer) || !IPAddress.TryParse(dnsServer, out IPAddress? parsedAddress))
        {
            return SystemDnsSwitchResult.Failure("The selected DNS endpoint is not a valid IP address.");
        }

        if (parsedAddress.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))
        {
            return SystemDnsSwitchResult.Failure("Only IPv4 and IPv6 DNS servers can be applied.");
        }

        if (PlatformEnvironment.IsWsl())
        {
            return ApplyToLinuxResolvConf(dnsServer, isWsl: true);
        }

        string[] targets = FindTargetInterfaces(parsedAddress.AddressFamily).ToArray();

        SystemDnsSwitchResult? networkManagerResult = TryApplyWithNetworkManager(dnsServer, parsedAddress.AddressFamily, targets);
        if (networkManagerResult is { Success: true })
        {
            return networkManagerResult;
        }

        SystemDnsSwitchResult? resolvectlResult = TryApplyWithResolvectl(dnsServer, targets);
        if (resolvectlResult is { Success: true })
        {
            return resolvectlResult;
        }

        SystemDnsSwitchResult resolvConfResult = ApplyToLinuxResolvConf(dnsServer, isWsl: false);
        if (resolvConfResult.Success)
        {
            return resolvConfResult;
        }

        if (networkManagerResult is { Success: false })
        {
            return networkManagerResult;
        }

        return resolvectlResult is { Success: false }
            ? resolvectlResult
            : resolvConfResult;
    }

    private static SystemDnsSwitchResult? TryApplyWithNetworkManager(
        string dnsServer,
        AddressFamily family,
        string[] targets)
    {
        if (targets.Length == 0 || !ProcessCommand.Exists("nmcli"))
        {
            return null;
        }

        var appliedTargets = new List<string>();

        foreach (string target in targets)
        {
            ProcessCommandResult connectionResult = ProcessCommand.Run(
                "nmcli",
                "-g",
                "GENERAL.CONNECTION",
                "device",
                "show",
                target);

            string connectionName = connectionResult.Output.Trim();
            if (!connectionResult.Success
                || string.IsNullOrWhiteSpace(connectionName)
                || string.Equals(connectionName, "--", StringComparison.Ordinal))
            {
                continue;
            }

            string dnsProperty = family == AddressFamily.InterNetwork ? "ipv4.dns" : "ipv6.dns";
            string ignoreAutoProperty = family == AddressFamily.InterNetwork ? "ipv4.ignore-auto-dns" : "ipv6.ignore-auto-dns";
            string verifyProperty = family == AddressFamily.InterNetwork ? "IP4.DNS" : "IP6.DNS";

            ProcessCommandResult modifyResult = ProcessCommand.Run(
                "nmcli",
                "connection",
                "modify",
                connectionName,
                ignoreAutoProperty,
                "yes",
                dnsProperty,
                dnsServer);

            if (!modifyResult.Success)
            {
                return SystemDnsSwitchResult.Failure(
                    $"NetworkManager rejected {target}: {modifyResult.CombinedOutput}");
            }

            ProcessCommandResult reapplyResult = ProcessCommand.Run("nmcli", "device", "reapply", target);
            if (!reapplyResult.Success)
            {
                ProcessCommandResult reconnectResult = ProcessCommand.Run("nmcli", "connection", "up", connectionName);
                if (!reconnectResult.Success)
                {
                    return SystemDnsSwitchResult.Failure(
                        $"NetworkManager could not reapply {target}: {reconnectResult.CombinedOutput}");
                }
            }

            ProcessCommandResult verifyResult = ProcessCommand.Run(
                "nmcli",
                "-g",
                verifyProperty,
                "device",
                "show",
                target);

            if (!verifyResult.Output.Contains(dnsServer, StringComparison.OrdinalIgnoreCase))
            {
                return SystemDnsSwitchResult.Failure(
                    $"NetworkManager did not confirm {dnsServer} on {target}.");
            }

            appliedTargets.Add(target);
        }

        if (appliedTargets.Count == 0)
        {
            return null;
        }

        TryFlushLinuxDnsCaches();

        string effectiveResolver = CurrentDnsStatusService.ReadEffectiveResolverSummary();
        return SystemDnsSwitchResult.Succeeded(
            $"Applied {dnsServer} via NetworkManager on {string.Join(", ", appliedTargets)}. Current Linux resolver: {effectiveResolver}.");
    }

    private static SystemDnsSwitchResult? TryApplyWithResolvectl(string dnsServer, string[] targets)
    {
        if (targets.Length == 0 || !ProcessCommand.Exists("resolvectl"))
        {
            return null;
        }

        foreach (string target in targets)
        {
            ProcessCommandResult applyResult = ProcessCommand.Run("resolvectl", "dns", target, dnsServer);
            if (!applyResult.Success)
            {
                return SystemDnsSwitchResult.Failure(
                    $"systemd-resolved rejected {target}: {applyResult.CombinedOutput}");
            }

            ProcessCommandResult verifyResult = ProcessCommand.Run("resolvectl", "status", target);
            if (!verifyResult.Output.Contains(dnsServer, StringComparison.OrdinalIgnoreCase))
            {
                return SystemDnsSwitchResult.Failure(
                    $"systemd-resolved did not confirm {dnsServer} on {target}.");
            }
        }

        TryFlushLinuxDnsCaches();

        string effectiveResolver = CurrentDnsStatusService.ReadEffectiveResolverSummary();
        return SystemDnsSwitchResult.Succeeded(
            $"Applied {dnsServer} via systemd-resolved on {string.Join(", ", targets)}. Current Linux resolver: {effectiveResolver}.");
    }

    private static SystemDnsSwitchResult ApplyToLinuxResolvConf(string dnsServer, bool isWsl)
    {
        try
        {
            BackupLinuxResolvConf();
            ReplaceLinuxResolvConf(dnsServer, isWsl);
            TryFlushLinuxDnsCaches();

            bool confirmed = CurrentDnsStatusService
                .ReadLinuxResolversFromResolvConf()
                .Any(address => string.Equals(address.ToString(), dnsServer, StringComparison.OrdinalIgnoreCase));

            if (!confirmed)
            {
                return SystemDnsSwitchResult.Failure($"Linux did not confirm {dnsServer} in {LinuxResolvConfPath}.");
            }

            string effectiveResolver = CurrentDnsStatusService.ReadEffectiveResolverSummary();
            string wslNote = isWsl && PlatformEnvironment.WslGeneratesResolvConf()
                ? " WSL may regenerate /etc/resolv.conf on restart until /etc/wsl.conf sets generateResolvConf=false."
                : string.Empty;

            return SystemDnsSwitchResult.Succeeded(
                $"Applied {dnsServer} via {LinuxResolvConfPath}. Current Linux resolver: {effectiveResolver}.{wslNote}");
        }
        catch (Exception ex)
        {
            return SystemDnsSwitchResult.Failure($"Failed to write {LinuxResolvConfPath}: {ex.Message}");
        }
    }

    private static string[] FindTargetInterfaces(AddressFamily selectedFamily)
    {
        return NetworkInterface.GetAllNetworkInterfaces()
            .Where(static networkInterface =>
                networkInterface.OperationalStatus == OperationalStatus.Up
                && networkInterface.NetworkInterfaceType is not NetworkInterfaceType.Loopback
                and not NetworkInterfaceType.Tunnel)
            .Where(HasUsableGateway)
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
        ProcessCommandResult clearResult = ProcessCommand.Run(
            "netsh.exe",
            "interface",
            family,
            "set",
            "dnsservers",
            $"name={interfaceName}",
            "source=static",
            "address=none",
            "validate=no");

        if (clearResult.Success)
        {
            return;
        }

        ProcessCommand.Run(
            "netsh.exe",
            "interface",
            family,
            "delete",
            "dnsservers",
            $"name={interfaceName}",
            "all",
            "validate=no");
    }

    private static async Task<SystemDnsSwitchResult> ReadResultAsync(string resultPath, CancellationToken cancellationToken)
    {
        string[] lines = await File.ReadAllLinesAsync(resultPath, cancellationToken).ConfigureAwait(false);

        if (lines.Length == 0)
        {
            return SystemDnsSwitchResult.Failure("The elevated DNS helper returned an empty response.");
        }

        bool success = string.Equals(lines[0], "success", StringComparison.OrdinalIgnoreCase);
        string message = lines.Length > 1 && !string.IsNullOrWhiteSpace(lines[1])
            ? lines[1]
            : success
                ? "DNS switch applied."
                : "The operating system rejected the DNS change.";

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

    private static string QuoteArgument(string value)
        => "\"" + value.Replace("\"", "\\\"", StringComparison.Ordinal) + "\"";

    private static void BackupLinuxResolvConf()
    {
        if (File.Exists(LinuxResolvConfBackupPath))
        {
            return;
        }

        if (!Path.Exists(LinuxResolvConfPath))
        {
            return;
        }

        File.WriteAllText(LinuxResolvConfBackupPath, File.ReadAllText(LinuxResolvConfPath), Encoding.UTF8);
    }

    private static void ReplaceLinuxResolvConf(string dnsServer, bool isWsl)
    {
        var resolvConfInfo = new FileInfo(LinuxResolvConfPath);
        if (resolvConfInfo.LinkTarget is not null)
        {
            resolvConfInfo.Delete();
        }

        File.WriteAllText(LinuxResolvConfPath, BuildLinuxResolvConfContents(dnsServer, isWsl), Encoding.UTF8);

        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        try
        {
            File.SetUnixFileMode(
                LinuxResolvConfPath,
                UnixFileMode.UserRead
                | UnixFileMode.UserWrite
                | UnixFileMode.GroupRead
                | UnixFileMode.OtherRead);
        }
        catch
        {
            // Permission normalization is best-effort only.
        }
    }

    private static string BuildLinuxResolvConfContents(string dnsServer, bool isWsl)
    {
        var builder = new StringBuilder();
        builder.AppendLine("# Managed by DNS Hop.");
        builder.AppendLine($"# Updated {DateTimeOffset.UtcNow:O}");
        builder.AppendLine($"nameserver {dnsServer}");
        builder.AppendLine("options timeout:2 attempts:2 rotate");

        if (isWsl)
        {
            builder.AppendLine("# WSL note: persistence across restarts requires /etc/wsl.conf");
            builder.AppendLine("# with [network] generateResolvConf=false.");
        }

        return builder.ToString();
    }

    private static void TryFlushLinuxDnsCaches()
    {
        if (ProcessCommand.Exists("resolvectl"))
        {
            ProcessCommand.Run("resolvectl", "flush-caches");
            return;
        }

        if (ProcessCommand.Exists("systemd-resolve"))
        {
            ProcessCommand.Run("systemd-resolve", "--flush-caches");
        }
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
}

internal sealed record SystemDnsSwitchResult(bool Success, string Message)
{
    public static SystemDnsSwitchResult Failure(string message) => new(false, message);

    public static SystemDnsSwitchResult Succeeded(string message) => new(true, message);
}
