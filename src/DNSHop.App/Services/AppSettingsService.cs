using DNSHop.App.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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

            string theme = TryGetString(root, "Theme") ?? "System";
            string language = TryGetString(root, "Language") ?? string.Empty;
            bool useMica = TryGetBool(root, "UseMica") ?? true;
            string lastNavSection = TryGetString(root, "LastNavSection") ?? "Home";
            int timeoutMilliseconds = TryGetInt(root, "TimeoutMilliseconds") ?? 2500;
            int concurrencyLimit = TryGetInt(root, "ConcurrencyLimit") ?? 8;
            int attemptsPerProbe = TryGetInt(root, "AttemptsPerProbe") ?? 3;
            bool autoUpdateListOnStartup = TryGetBool(root, "AutoUpdateListOnStartup") ?? true;
            bool checkForAppUpdatesOnStartup = TryGetBool(root, "CheckForAppUpdatesOnStartup") ?? true;
            string outboundProxyType = TryGetString(root, "OutboundProxyType") ?? "None";
            string outboundProxyHost = TryGetString(root, "OutboundProxyHost") ?? string.Empty;
            int outboundProxyPort = TryGetInt(root, "OutboundProxyPort") ?? 1080;
            DnsServerDefinition[] customServers = TryGetCustomServers(root);
            string[] sidelinedKeys = TryGetSidelinedKeys(root);
            string? activeProfileId = TryGetString(root, "ActiveProfileId");
            DnsProfile[] profiles = TryGetProfiles(root);
            AppliedDnsEntry[] applyHistory = TryGetApplyHistory(root);

            return new AppSettings
            {
                Theme = NormalizeTheme(theme),
                Language = language?.Trim() ?? string.Empty,
                UseMica = useMica,
                LastNavSection = string.IsNullOrWhiteSpace(lastNavSection) ? "Home" : lastNavSection.Trim(),
                TimeoutMilliseconds = Math.Clamp(timeoutMilliseconds, 250, 10000),
                ConcurrencyLimit = Math.Clamp(concurrencyLimit, 1, 32),
                AttemptsPerProbe = Math.Clamp(attemptsPerProbe, 1, 5),
                AutoUpdateListOnStartup = autoUpdateListOnStartup,
                CheckForAppUpdatesOnStartup = checkForAppUpdatesOnStartup,
                OutboundProxyType = NormalizeProxyType(outboundProxyType),
                OutboundProxyHost = NormalizeProxyHost(outboundProxyHost),
                OutboundProxyPort = Math.Clamp(outboundProxyPort, 1, 65535),
                CustomServers = customServers,
                SidelinedServerKeys = sidelinedKeys,
                ActiveProfileId = string.IsNullOrWhiteSpace(activeProfileId) ? null : activeProfileId,
                Profiles = profiles,
                ApplyHistory = applyHistory,
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
                Language = settings.Language?.Trim() ?? string.Empty,
                UseMica = settings.UseMica,
                LastNavSection = string.IsNullOrWhiteSpace(settings.LastNavSection) ? "Home" : settings.LastNavSection.Trim(),
                TimeoutMilliseconds = Math.Clamp(settings.TimeoutMilliseconds, 250, 10000),
                ConcurrencyLimit = Math.Clamp(settings.ConcurrencyLimit, 1, 32),
                AttemptsPerProbe = Math.Clamp(settings.AttemptsPerProbe, 1, 5),
                AutoUpdateListOnStartup = settings.AutoUpdateListOnStartup,
                CheckForAppUpdatesOnStartup = settings.CheckForAppUpdatesOnStartup,
                OutboundProxyType = NormalizeProxyType(settings.OutboundProxyType),
                OutboundProxyHost = NormalizeProxyHost(settings.OutboundProxyHost),
                OutboundProxyPort = Math.Clamp(settings.OutboundProxyPort, 1, 65535),
                CustomServers = NormalizeCustomServers(settings.CustomServers),
                SidelinedServerKeys = (settings.SidelinedServerKeys ?? []).Where(k => !string.IsNullOrWhiteSpace(k)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
                ActiveProfileId = settings.ActiveProfileId,
                Profiles = settings.Profiles ?? [],
                ApplyHistory = TrimHistory(settings.ApplyHistory),
            };

            using var stream = new MemoryStream();
            using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true }))
            {
                writer.WriteStartObject();
                writer.WriteString("Theme", normalized.Theme);
                writer.WriteString("Language", normalized.Language);
                writer.WriteBoolean("UseMica", normalized.UseMica);
                writer.WriteString("LastNavSection", normalized.LastNavSection);
                writer.WriteNumber("TimeoutMilliseconds", normalized.TimeoutMilliseconds);
                writer.WriteNumber("ConcurrencyLimit", normalized.ConcurrencyLimit);
                writer.WriteNumber("AttemptsPerProbe", normalized.AttemptsPerProbe);
                writer.WriteBoolean("AutoUpdateListOnStartup", normalized.AutoUpdateListOnStartup);
                writer.WriteBoolean("CheckForAppUpdatesOnStartup", normalized.CheckForAppUpdatesOnStartup);
                writer.WriteString("OutboundProxyType", normalized.OutboundProxyType);
                writer.WriteString("OutboundProxyHost", normalized.OutboundProxyHost);
                writer.WriteNumber("OutboundProxyPort", normalized.OutboundProxyPort);

                if (!string.IsNullOrEmpty(normalized.ActiveProfileId))
                {
                    writer.WriteString("ActiveProfileId", normalized.ActiveProfileId);
                }

                if (normalized.SidelinedServerKeys.Length > 0)
                {
                    writer.WritePropertyName("SidelinedServerKeys");
                    writer.WriteStartArray();
                    foreach (var key in normalized.SidelinedServerKeys)
                    {
                        writer.WriteStringValue(key);
                    }
                    writer.WriteEndArray();
                }

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

                if (normalized.Profiles.Length > 0)
                {
                    writer.WritePropertyName("Profiles");
                    writer.WriteStartArray();
                    foreach (DnsProfile profile in normalized.Profiles)
                    {
                        WriteProfile(writer, profile);
                    }
                    writer.WriteEndArray();
                }

                if (normalized.ApplyHistory.Length > 0)
                {
                    writer.WritePropertyName("ApplyHistory");
                    writer.WriteStartArray();
                    foreach (AppliedDnsEntry entry in normalized.ApplyHistory)
                    {
                        WriteHistoryEntry(writer, entry);
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
        AppDiagnostics.WriteError(
            "Settings",
            $"Failed to {operation} settings at '{_settingsPath}'.",
            exception);
    }

    private static string NormalizeTheme(string? theme)
    {
        if (string.Equals(theme, "Light", StringComparison.OrdinalIgnoreCase))
        {
            return "Light";
        }

        if (string.Equals(theme, "Dark", StringComparison.OrdinalIgnoreCase))
        {
            return "Dark";
        }

        return "System";
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

    private static string[] TryGetSidelinedKeys(JsonElement root)
    {
        if (!root.TryGetProperty("SidelinedServerKeys", out JsonElement value)
            || value.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        var keys = new List<string>();
        foreach (var item in value.EnumerateArray())
        {
            if (item.ValueKind == JsonValueKind.String && item.GetString() is { Length: > 0 } s)
            {
                keys.Add(s);
            }
        }

        return keys.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static DnsProfile[] TryGetProfiles(JsonElement root)
    {
        if (!root.TryGetProperty("Profiles", out JsonElement value)
            || value.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        var profiles = new List<DnsProfile>();
        foreach (JsonElement item in value.EnumerateArray())
        {
            string? id = TryGetString(item, "Id");
            string? name = TryGetString(item, "Name");
            if (string.IsNullOrWhiteSpace(id) || string.IsNullOrWhiteSpace(name))
            {
                continue;
            }

            string? protocolName = TryGetString(item, "EncryptedProtocol");
            Enum.TryParse(protocolName, ignoreCase: true, out DnsProtocol protocol);

            profiles.Add(new DnsProfile
            {
                Id = id,
                Name = name,
                Description = TryGetString(item, "Description"),
                PreferredIPv4 = TryGetString(item, "PreferredIPv4"),
                AlternateIPv4 = TryGetString(item, "AlternateIPv4"),
                PreferredIPv6 = TryGetString(item, "PreferredIPv6"),
                AlternateIPv6 = TryGetString(item, "AlternateIPv6"),
                EncryptedEndpoint = TryGetString(item, "EncryptedEndpoint"),
                EncryptedProtocol = protocol,
                IsBuiltIn = TryGetBool(item, "IsBuiltIn") ?? false,
                BuiltInKey = TryGetString(item, "BuiltInKey"),
            });
        }

        return profiles.ToArray();
    }

    private static AppliedDnsEntry[] TryGetApplyHistory(JsonElement root)
    {
        if (!root.TryGetProperty("ApplyHistory", out JsonElement value)
            || value.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        var entries = new List<AppliedDnsEntry>();
        foreach (JsonElement item in value.EnumerateArray())
        {
            string? label = TryGetString(item, "DisplayLabel");
            string? whenStr = TryGetString(item, "AppliedAt");
            if (string.IsNullOrWhiteSpace(label) || !DateTimeOffset.TryParse(whenStr, out var when))
            {
                continue;
            }

            entries.Add(new AppliedDnsEntry
            {
                AppliedAt = when,
                DisplayLabel = label,
                PreferredIPv4 = TryGetString(item, "PreferredIPv4"),
                AlternateIPv4 = TryGetString(item, "AlternateIPv4"),
                PreferredIPv6 = TryGetString(item, "PreferredIPv6"),
                AlternateIPv6 = TryGetString(item, "AlternateIPv6"),
                ProfileId = TryGetString(item, "ProfileId"),
            });
        }

        return TrimHistory(entries.ToArray());
    }

    private static AppliedDnsEntry[] TrimHistory(AppliedDnsEntry[]? entries)
    {
        if (entries is null || entries.Length == 0)
        {
            return [];
        }

        return entries
            .OrderByDescending(e => e.AppliedAt)
            .Take(5)
            .ToArray();
    }

    private static void WriteProfile(Utf8JsonWriter writer, DnsProfile profile)
    {
        writer.WriteStartObject();
        writer.WriteString("Id", profile.Id);
        writer.WriteString("Name", profile.Name);
        if (!string.IsNullOrWhiteSpace(profile.Description))
        {
            writer.WriteString("Description", profile.Description);
        }
        if (!string.IsNullOrWhiteSpace(profile.PreferredIPv4))
        {
            writer.WriteString("PreferredIPv4", profile.PreferredIPv4);
        }
        if (!string.IsNullOrWhiteSpace(profile.AlternateIPv4))
        {
            writer.WriteString("AlternateIPv4", profile.AlternateIPv4);
        }
        if (!string.IsNullOrWhiteSpace(profile.PreferredIPv6))
        {
            writer.WriteString("PreferredIPv6", profile.PreferredIPv6);
        }
        if (!string.IsNullOrWhiteSpace(profile.AlternateIPv6))
        {
            writer.WriteString("AlternateIPv6", profile.AlternateIPv6);
        }
        if (!string.IsNullOrWhiteSpace(profile.EncryptedEndpoint))
        {
            writer.WriteString("EncryptedEndpoint", profile.EncryptedEndpoint);
            writer.WriteString("EncryptedProtocol", profile.EncryptedProtocol.ToString());
        }
        if (profile.IsBuiltIn)
        {
            writer.WriteBoolean("IsBuiltIn", true);
            if (!string.IsNullOrWhiteSpace(profile.BuiltInKey))
            {
                writer.WriteString("BuiltInKey", profile.BuiltInKey);
            }
        }
        writer.WriteEndObject();
    }

    private static void WriteHistoryEntry(Utf8JsonWriter writer, AppliedDnsEntry entry)
    {
        writer.WriteStartObject();
        writer.WriteString("AppliedAt", entry.AppliedAt.ToString("O"));
        writer.WriteString("DisplayLabel", entry.DisplayLabel);
        if (!string.IsNullOrWhiteSpace(entry.PreferredIPv4))
        {
            writer.WriteString("PreferredIPv4", entry.PreferredIPv4);
        }
        if (!string.IsNullOrWhiteSpace(entry.AlternateIPv4))
        {
            writer.WriteString("AlternateIPv4", entry.AlternateIPv4);
        }
        if (!string.IsNullOrWhiteSpace(entry.PreferredIPv6))
        {
            writer.WriteString("PreferredIPv6", entry.PreferredIPv6);
        }
        if (!string.IsNullOrWhiteSpace(entry.AlternateIPv6))
        {
            writer.WriteString("AlternateIPv6", entry.AlternateIPv6);
        }
        if (!string.IsNullOrWhiteSpace(entry.ProfileId))
        {
            writer.WriteString("ProfileId", entry.ProfileId);
        }
        writer.WriteEndObject();
    }
}
