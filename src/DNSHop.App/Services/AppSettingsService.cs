using DNSHop.App.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text.Json;

namespace DNSHop.App.Services;

internal sealed class AppSettingsService
{
    private readonly string _settingsPath;

    public AppSettingsService()
    {
        string root = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(root))
        {
            root = Path.GetTempPath();
        }

        string folder = Path.Combine(root, "DNS Hop");
        _settingsPath = Path.Combine(folder, "settings.json");
    }

    public AppSettings Load()
    {
        try
        {
            if (!File.Exists(_settingsPath))
            {
                return new AppSettings();
            }

            string json = File.ReadAllText(_settingsPath);
            using var document = JsonDocument.Parse(json);
            JsonElement root = document.RootElement;

            string theme = TryGetString(root, "Theme") ?? "Dark";
            int timeoutMilliseconds = TryGetInt(root, "TimeoutMilliseconds") ?? 2500;
            int concurrencyLimit = TryGetInt(root, "ConcurrencyLimit") ?? 8;
            int attemptsPerProbe = TryGetInt(root, "AttemptsPerProbe") ?? 3;
            bool autoUpdateListOnStartup = TryGetBool(root, "AutoUpdateListOnStartup") ?? true;
            bool checkForAppUpdatesOnStartup = TryGetBool(root, "CheckForAppUpdatesOnStartup") ?? true;
            string outboundProxyType = TryGetString(root, "OutboundProxyType") ?? "None";
            string outboundProxyHost = TryGetString(root, "OutboundProxyHost") ?? string.Empty;
            int outboundProxyPort = TryGetInt(root, "OutboundProxyPort") ?? 1080;
            DnsServerDefinition[] customServers = TryGetCustomServers(root);

            return new AppSettings
            {
                Theme = NormalizeTheme(theme),
                TimeoutMilliseconds = Math.Clamp(timeoutMilliseconds, 250, 10000),
                ConcurrencyLimit = Math.Clamp(concurrencyLimit, 1, 64),
                AttemptsPerProbe = Math.Clamp(attemptsPerProbe, 1, 5),
                AutoUpdateListOnStartup = autoUpdateListOnStartup,
                CheckForAppUpdatesOnStartup = checkForAppUpdatesOnStartup,
                OutboundProxyType = NormalizeProxyType(outboundProxyType),
                OutboundProxyHost = NormalizeProxyHost(outboundProxyHost),
                OutboundProxyPort = Math.Clamp(outboundProxyPort, 1, 65535),
                CustomServers = customServers,
            };
        }
        catch (Exception ex)
        {
            LogPersistenceError("load", ex);
            return new AppSettings();
        }
    }

    public void Save(AppSettings settings)
    {
        try
        {
            string? directory = Path.GetDirectoryName(_settingsPath);
            if (string.IsNullOrWhiteSpace(directory))
            {
                return;
            }

            Directory.CreateDirectory(directory);

            var normalized = new AppSettings
            {
                Theme = NormalizeTheme(settings.Theme),
                TimeoutMilliseconds = Math.Clamp(settings.TimeoutMilliseconds, 250, 10000),
                ConcurrencyLimit = Math.Clamp(settings.ConcurrencyLimit, 1, 64),
                AttemptsPerProbe = Math.Clamp(settings.AttemptsPerProbe, 1, 5),
                AutoUpdateListOnStartup = settings.AutoUpdateListOnStartup,
                CheckForAppUpdatesOnStartup = settings.CheckForAppUpdatesOnStartup,
                OutboundProxyType = NormalizeProxyType(settings.OutboundProxyType),
                OutboundProxyHost = NormalizeProxyHost(settings.OutboundProxyHost),
                OutboundProxyPort = Math.Clamp(settings.OutboundProxyPort, 1, 65535),
                CustomServers = NormalizeCustomServers(settings.CustomServers),
            };

            using var stream = new MemoryStream();
            using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true }))
            {
                writer.WriteStartObject();
                writer.WriteString("Theme", normalized.Theme);
                writer.WriteNumber("TimeoutMilliseconds", normalized.TimeoutMilliseconds);
                writer.WriteNumber("ConcurrencyLimit", normalized.ConcurrencyLimit);
                writer.WriteNumber("AttemptsPerProbe", normalized.AttemptsPerProbe);
                writer.WriteBoolean("AutoUpdateListOnStartup", normalized.AutoUpdateListOnStartup);
                writer.WriteBoolean("CheckForAppUpdatesOnStartup", normalized.CheckForAppUpdatesOnStartup);
                writer.WriteString("OutboundProxyType", normalized.OutboundProxyType);
                writer.WriteString("OutboundProxyHost", normalized.OutboundProxyHost);
                writer.WriteNumber("OutboundProxyPort", normalized.OutboundProxyPort);

                if (normalized.CustomServers.Length > 0)
                {
                    writer.WritePropertyName("CustomServers");
                    writer.WriteStartArray();

                    foreach (DnsServerDefinition server in normalized.CustomServers)
                    {
                        writer.WriteStartObject();
                        writer.WriteString("Provider", server.Provider);
                        writer.WriteString("Protocol", server.Protocol.ToString());
                        writer.WriteString("AddressOrHost", server.AddressOrHost);
                        writer.WriteNumber("Port", server.Port);

                        if (!string.IsNullOrWhiteSpace(server.DohEndpoint))
                        {
                            writer.WriteString("DohEndpoint", server.DohEndpoint);
                        }

                        if (!string.IsNullOrWhiteSpace(server.DotTlsHost))
                        {
                            writer.WriteString("DotTlsHost", server.DotTlsHost);
                        }

                        writer.WriteBoolean("IsPinned", server.IsPinned);
                        writer.WriteBoolean("IsSidelined", server.IsSidelined);
                        writer.WriteEndObject();
                    }

                    writer.WriteEndArray();
                }

                writer.WriteEndObject();
            }

            File.WriteAllBytes(_settingsPath, stream.ToArray());
        }
        catch (Exception ex)
        {
            LogPersistenceError("save", ex);
        }
    }

    private void LogPersistenceError(string operation, Exception exception)
    {
        try
        {
            string? directory = Path.GetDirectoryName(_settingsPath);
            if (string.IsNullOrWhiteSpace(directory))
            {
                directory = Path.Combine(Path.GetTempPath(), "DNS Hop");
            }

            Directory.CreateDirectory(directory);

            string logPath = Path.Combine(directory, "settings-errors.log");
            string line =
                $"{DateTime.UtcNow:O} [{operation}] {exception.GetType().Name}: {exception.Message}{Environment.NewLine}";
            File.AppendAllText(logPath, line);
        }
        catch
        {
            // Never throw from diagnostics.
        }
    }

    private static string NormalizeTheme(string? theme)
    {
        return string.Equals(theme, "Light", StringComparison.OrdinalIgnoreCase)
            ? "Light"
            : "Dark";
    }

    private static string NormalizeProxyType(string? proxyType)
    {
        if (string.Equals(proxyType, "Https", StringComparison.OrdinalIgnoreCase))
        {
            return "Https";
        }

        if (string.Equals(proxyType, "Socks4", StringComparison.OrdinalIgnoreCase))
        {
            return "Socks4";
        }

        if (string.Equals(proxyType, "Socks5", StringComparison.OrdinalIgnoreCase))
        {
            return "Socks5";
        }

        return "None";
    }

    private static string NormalizeProxyHost(string? proxyHost)
    {
        return proxyHost?.Trim() ?? string.Empty;
    }

    private static string? TryGetString(JsonElement root, string propertyName)
    {
        if (root.TryGetProperty(propertyName, out JsonElement value)
            && value.ValueKind == JsonValueKind.String)
        {
            return value.GetString();
        }

        return null;
    }

    private static int? TryGetInt(JsonElement root, string propertyName)
    {
        if (root.TryGetProperty(propertyName, out JsonElement value)
            && value.ValueKind == JsonValueKind.Number
            && value.TryGetInt32(out int parsed))
        {
            return parsed;
        }

        return null;
    }

    private static bool? TryGetBool(JsonElement root, string propertyName)
    {
        if (root.TryGetProperty(propertyName, out JsonElement value)
            && (value.ValueKind == JsonValueKind.True || value.ValueKind == JsonValueKind.False))
        {
            return value.GetBoolean();
        }

        return null;
    }

    private static DnsServerDefinition[] TryGetCustomServers(JsonElement root)
    {
        if (!root.TryGetProperty("CustomServers", out JsonElement value)
            || value.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        var servers = new List<DnsServerDefinition>();

        foreach (JsonElement item in value.EnumerateArray())
        {
            if (TryParseCustomServer(item, out DnsServerDefinition? server))
            {
                servers.Add(server);
            }
        }

        return NormalizeCustomServers(servers);
    }

    private static bool TryParseCustomServer(JsonElement item, out DnsServerDefinition server)
    {
        server = null!;

        string provider = TryGetString(item, "Provider") ?? "Custom DNS";
        string? protocolName = TryGetString(item, "Protocol");
        string? addressOrHost = TryGetString(item, "AddressOrHost");
        int port = TryGetInt(item, "Port") ?? 0;
        bool isPinned = TryGetBool(item, "IsPinned") ?? false;
        bool isSidelined = TryGetBool(item, "IsSidelined") ?? false;

        if (!TryParseProtocol(protocolName, out DnsProtocol protocol))
        {
            return false;
        }

        DnsServerDefinition? parsed = protocol switch
        {
            DnsProtocol.UdpTcp => BuildClassicCustomServer(addressOrHost, provider, port),
            DnsProtocol.Doh => BuildDohCustomServer(TryGetString(item, "DohEndpoint") ?? addressOrHost, provider),
            DnsProtocol.Dot => BuildDotCustomServer(addressOrHost, TryGetString(item, "DotTlsHost"), provider, port),
            _ => null,
        };

        if (parsed is null)
        {
            return false;
        }

        parsed.IsPinned = isPinned;
        parsed.IsSidelined = isSidelined;
        parsed.IsCustom = true;
        server = parsed;
        return true;
    }

    private static DnsServerDefinition[] NormalizeCustomServers(IEnumerable<DnsServerDefinition>? servers)
    {
        if (servers is null)
        {
            return [];
        }

        var unique = new List<DnsServerDefinition>();
        var seenKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (DnsServerDefinition server in servers)
        {
            DnsServerDefinition? normalized = server.Protocol switch
            {
                DnsProtocol.UdpTcp => BuildClassicCustomServer(server.AddressOrHost, server.Provider, server.Port),
                DnsProtocol.Doh => BuildDohCustomServer(server.DohEndpoint ?? server.AddressOrHost, server.Provider),
                DnsProtocol.Dot => BuildDotCustomServer(server.AddressOrHost, server.DotTlsHost, server.Provider, server.Port),
                _ => null,
            };

            if (normalized is null)
            {
                continue;
            }

            normalized.IsPinned = server.IsPinned;
            normalized.IsSidelined = server.IsSidelined;
            normalized.IsCustom = true;

            if (seenKeys.Add(BuildServerKey(normalized)))
            {
                unique.Add(normalized);
            }
        }

        return unique.ToArray();
    }

    private static DnsServerDefinition? BuildClassicCustomServer(string? addressOrHost, string provider, int port)
    {
        string normalizedAddress = addressOrHost?.Trim() ?? string.Empty;
        if (!IPAddress.TryParse(normalizedAddress, out IPAddress? ipAddress))
        {
            return null;
        }

        return DnsServerDefinition.CreateUdpTcp(ipAddress.ToString(), NormalizeProvider(provider), NormalizePort(port, 53));
    }

    private static DnsServerDefinition? BuildDohCustomServer(string? endpoint, string provider)
    {
        if (!Uri.TryCreate(endpoint?.Trim(), UriKind.Absolute, out Uri? uri)
            || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return DnsServerDefinition.CreateDoh(uri.AbsoluteUri, NormalizeProvider(provider));
    }

    private static DnsServerDefinition? BuildDotCustomServer(
        string? addressOrHost,
        string? dotTlsHost,
        string provider,
        int port)
    {
        string normalizedAddress = addressOrHost?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(normalizedAddress))
        {
            return null;
        }

        string normalizedTlsHost = string.IsNullOrWhiteSpace(dotTlsHost)
            ? normalizedAddress
            : dotTlsHost.Trim();

        return DnsServerDefinition.CreateDot(
            normalizedAddress,
            normalizedTlsHost,
            NormalizeProvider(provider),
            NormalizePort(port, 853));
    }

    private static bool TryParseProtocol(string? value, out DnsProtocol protocol)
    {
        protocol = DnsProtocol.UdpTcp;
        return Enum.TryParse(value, ignoreCase: true, out protocol);
    }

    private static int NormalizePort(int value, int fallback)
    {
        return value is >= 1 and <= 65535 ? value : fallback;
    }

    private static string NormalizeProvider(string? provider)
    {
        return string.IsNullOrWhiteSpace(provider) ? "Custom DNS" : provider.Trim();
    }

    private static string BuildServerKey(DnsServerDefinition server)
    {
        return $"{server.Protocol}|{server.EndpointDisplay}";
    }
}
