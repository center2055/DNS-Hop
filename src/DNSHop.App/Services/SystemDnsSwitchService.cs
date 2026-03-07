using DNSHop.App.Models;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using JsonDocument = System.Text.Json.JsonDocument;

namespace DNSHop.App.Services;

internal sealed class SystemDnsSwitchService
{
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

        if (!IPAddress.TryParse(server.AddressOrHost, out _))
        {
            return "The selected DNS endpoint does not expose a direct IP address.";
        }

        return null;
    }

    public async Task<SystemDnsSwitchResult> ApplyAsync(DnsServerDefinition server, CancellationToken cancellationToken)
    {
        if (TryGetUnsupportedReason(server) is { } reason)
        {
            return SystemDnsSwitchResult.Failure(reason);
        }

        string resultPath = Path.Combine(
            Path.GetTempPath(),
            $"dnshop-system-dns-{Guid.NewGuid():N}.json");

        try
        {
            string script = BuildPowerShellScript(server.AddressOrHost, resultPath);
            var startInfo = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {EncodePowerShellCommand(script)}",
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
                var payload = await ReadResultAsync(resultPath, cancellationToken).ConfigureAwait(false);
                return payload.Success
                    ? SystemDnsSwitchResult.Succeeded(payload.Message ?? $"Applied {server.AddressOrHost}.")
                    : SystemDnsSwitchResult.Failure(payload.Message ?? "Windows rejected the DNS change.");
            }

            return process.ExitCode == 0
                ? SystemDnsSwitchResult.Succeeded($"Applied {server.AddressOrHost} to active adapters.")
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

    private static async Task<SystemDnsSwitchPayload> ReadResultAsync(string resultPath, CancellationToken cancellationToken)
    {
        await using var stream = File.OpenRead(resultPath);
        using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
        var root = document.RootElement;

        bool success = root.TryGetProperty("Success", out var successProperty)
            && successProperty.ValueKind is System.Text.Json.JsonValueKind.True or System.Text.Json.JsonValueKind.False
            && successProperty.GetBoolean();

        string? message = root.TryGetProperty("Message", out var messageProperty)
            && messageProperty.ValueKind == System.Text.Json.JsonValueKind.String
                ? messageProperty.GetString()
                : null;

        return new SystemDnsSwitchPayload
        {
            Success = success,
            Message = message ?? "Windows returned an empty DNS switch response.",
        };
    }

    private static string BuildPowerShellScript(string dnsServer, string resultPath)
    {
        string escapedDnsServer = EscapeSingleQuotedPowerShellString(dnsServer);
        string escapedResultPath = EscapeSingleQuotedPowerShellString(resultPath);

        return $$"""
$ErrorActionPreference = 'Stop'
$dnsServer = '{{escapedDnsServer}}'
$resultPath = '{{escapedResultPath}}'

try {
    $targets = @(
        Get-NetIPConfiguration |
        Where-Object {
            $_.NetAdapter -and
            $_.NetAdapter.Status -eq 'Up' -and
            ($_.IPv4DefaultGateway -ne $null -or $_.IPv6DefaultGateway -ne $null)
        } |
        Select-Object InterfaceIndex, InterfaceAlias |
        Sort-Object InterfaceIndex -Unique
    )

    if (-not $targets) {
        $targets = @(
            Get-NetAdapter |
            Where-Object {
                $_.Status -eq 'Up' -and
                $_.HardwareInterface
            } |
            Select-Object InterfaceIndex, InterfaceAlias |
            Sort-Object InterfaceIndex -Unique
        )
    }

    if (-not $targets) {
        throw 'No active network adapters were found.'
    }

    foreach ($target in $targets) {
        Set-DnsClientServerAddress -InterfaceIndex $target.InterfaceIndex -ServerAddresses $dnsServer -ErrorAction Stop
    }

    @{
        Success = $true
        Message = "Applied DNS server $dnsServer to: $($targets.InterfaceAlias -join ', ')"
    } | ConvertTo-Json -Compress | Set-Content -Path $resultPath -Encoding UTF8

    exit 0
}
catch {
    @{
        Success = $false
        Message = $_.Exception.Message
    } | ConvertTo-Json -Compress | Set-Content -Path $resultPath -Encoding UTF8

    exit 1
}
""";
    }

    private static string EncodePowerShellCommand(string command)
        => Convert.ToBase64String(Encoding.Unicode.GetBytes(command));

    private static string EscapeSingleQuotedPowerShellString(string value)
        => value.Replace("'", "''", StringComparison.Ordinal);

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

    private sealed class SystemDnsSwitchPayload
    {
        public bool Success { get; set; }

        public string? Message { get; set; }
    }
}

internal sealed record SystemDnsSwitchResult(bool Success, string Message)
{
    public static SystemDnsSwitchResult Failure(string message) => new(false, message);

    public static SystemDnsSwitchResult Succeeded(string message) => new(true, message);
}
