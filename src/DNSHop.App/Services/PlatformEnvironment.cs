using System;
using System.IO;

namespace DNSHop.App.Services;

internal static class PlatformEnvironment
{
    private static bool? _isWsl;
    private static bool? _wslGeneratesResolvConf;

    public static bool IsWsl()
    {
        if (!OperatingSystem.IsLinux())
        {
            return false;
        }

        if (_isWsl is bool cached)
        {
            return cached;
        }

        if (!string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("WSL_DISTRO_NAME"))
            || !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("WSL_INTEROP")))
        {
            _isWsl = true;
            return true;
        }

        try
        {
            string procVersion = File.ReadAllText("/proc/version");
            _isWsl = procVersion.Contains("microsoft", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            _isWsl = false;
        }

        return _isWsl.Value;
    }

    public static bool WslGeneratesResolvConf()
    {
        if (!IsWsl())
        {
            return false;
        }

        if (_wslGeneratesResolvConf is bool cached)
        {
            return cached;
        }

        const string configPath = "/etc/wsl.conf";
        if (!File.Exists(configPath))
        {
            _wslGeneratesResolvConf = true;
            return true;
        }

        bool inNetworkSection = false;

        try
        {
            foreach (string rawLine in File.ReadLines(configPath))
            {
                string line = rawLine.Trim();

                if (line.Length == 0 || line.StartsWith('#') || line.StartsWith(';'))
                {
                    continue;
                }

                if (line.StartsWith('[') && line.EndsWith(']'))
                {
                    inNetworkSection = string.Equals(
                        line[1..^1].Trim(),
                        "network",
                        StringComparison.OrdinalIgnoreCase);
                    continue;
                }

                if (!inNetworkSection)
                {
                    continue;
                }

                int separatorIndex = line.IndexOf('=');
                if (separatorIndex < 0)
                {
                    continue;
                }

                string key = line[..separatorIndex].Trim();
                if (!string.Equals(key, "generateResolvConf", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                string value = line[(separatorIndex + 1)..].Trim();
                _wslGeneratesResolvConf = !value.Equals("false", StringComparison.OrdinalIgnoreCase);
                return _wslGeneratesResolvConf.Value;
            }
        }
        catch
        {
            _wslGeneratesResolvConf = true;
            return true;
        }

        _wslGeneratesResolvConf = true;
        return true;
    }

    public static string DisplayName =>
        OperatingSystem.IsWindows()
            ? "Windows"
            : OperatingSystem.IsLinux()
                ? IsWsl()
                    ? "Linux (WSL)"
                    : "Linux"
                : OperatingSystem.IsMacOS()
                    ? "macOS"
                    : "this platform";
}
