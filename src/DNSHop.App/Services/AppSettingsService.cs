using System;
using System.IO;
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
            int attemptsPerProbe = TryGetInt(root, "AttemptsPerProbe") ?? 1;
            bool autoUpdateListOnStartup = TryGetBool(root, "AutoUpdateListOnStartup") ?? true;
            string outboundProxyType = TryGetString(root, "OutboundProxyType") ?? "None";
            string outboundProxyHost = TryGetString(root, "OutboundProxyHost") ?? string.Empty;
            int outboundProxyPort = TryGetInt(root, "OutboundProxyPort") ?? 1080;

            return new AppSettings
            {
                Theme = NormalizeTheme(theme),
                TimeoutMilliseconds = Math.Clamp(timeoutMilliseconds, 250, 10000),
                ConcurrencyLimit = Math.Clamp(concurrencyLimit, 1, 64),
                AttemptsPerProbe = Math.Clamp(attemptsPerProbe, 1, 5),
                AutoUpdateListOnStartup = autoUpdateListOnStartup,
                OutboundProxyType = NormalizeProxyType(outboundProxyType),
                OutboundProxyHost = NormalizeProxyHost(outboundProxyHost),
                OutboundProxyPort = Math.Clamp(outboundProxyPort, 1, 65535),
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
                OutboundProxyType = NormalizeProxyType(settings.OutboundProxyType),
                OutboundProxyHost = NormalizeProxyHost(settings.OutboundProxyHost),
                OutboundProxyPort = Math.Clamp(settings.OutboundProxyPort, 1, 65535),
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
                writer.WriteString("OutboundProxyType", normalized.OutboundProxyType);
                writer.WriteString("OutboundProxyHost", normalized.OutboundProxyHost);
                writer.WriteNumber("OutboundProxyPort", normalized.OutboundProxyPort);
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
}
