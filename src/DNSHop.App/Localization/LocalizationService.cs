using Avalonia.Platform;
using DNSHop.App.Services;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DNSHop.App.Localization;

public sealed class LocalizationService : ILocalizationService
{
    public static LocalizationService Instance { get; } = new();

    private static readonly LanguageDescriptor[] Languages =
    [
        new("en", "English", "English"),
        new("de", "Deutsch", "German"),
        new("fr", "Français", "French"),
        new("ru", "Русский", "Russian"),
        new("zh-CN", "简体中文", "Chinese (Simplified)"),
    ];

    private readonly Dictionary<string, Dictionary<string, string>> _bundles = new(StringComparer.OrdinalIgnoreCase);
    private string _currentCulture = "en";
    private Dictionary<string, string> _active = new(StringComparer.Ordinal);
    private Dictionary<string, string> _fallback = new(StringComparer.Ordinal);

    private bool _loaded;

    private LocalizationService()
    {
    }

    public void EnsureLoaded()
    {
        if (_loaded)
        {
            return;
        }

        LoadAllBundles();
        _fallback = _bundles.TryGetValue("en", out var en) ? en : new Dictionary<string, string>();
        _active = _fallback;
        _loaded = true;
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public event EventHandler? CultureChanged;

    public string CurrentCulture => _currentCulture;

    public IReadOnlyList<LanguageDescriptor> AvailableLanguages => Languages;

    public string this[string key]
    {
        get
        {
            if (string.IsNullOrEmpty(key))
            {
                return string.Empty;
            }

            if (_active.TryGetValue(key, out var value))
            {
                return value;
            }

            if (_fallback.TryGetValue(key, out var fallbackValue))
            {
                return fallbackValue;
            }

            return key;
        }
    }

    public void SetCulture(string culture)
    {
        if (string.IsNullOrWhiteSpace(culture))
        {
            return;
        }

        var resolved = ResolveCulture(culture);
        if (string.Equals(resolved, _currentCulture, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        _currentCulture = resolved;
        _active = _bundles.TryGetValue(resolved, out var bundle) ? bundle : _fallback;

        try
        {
            CultureInfo.CurrentUICulture = new CultureInfo(resolved);
        }
        catch (CultureNotFoundException)
        {
        }

        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(Binding.IndexerName));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(CurrentCulture)));
        CultureChanged?.Invoke(this, EventArgs.Empty);
    }

    public static string DetectSystemCulture()
    {
        var ui = CultureInfo.CurrentUICulture;
        if (ui.Name.StartsWith("zh", StringComparison.OrdinalIgnoreCase))
        {
            return "zh-CN";
        }

        return ui.TwoLetterISOLanguageName.ToLowerInvariant() switch
        {
            "de" => "de",
            "fr" => "fr",
            "ru" => "ru",
            _ => "en",
        };
    }

    private string ResolveCulture(string requested)
    {
        if (_bundles.ContainsKey(requested))
        {
            return requested;
        }

        var prefix = requested.Split('-', '_')[0];
        if (_bundles.ContainsKey(prefix))
        {
            return prefix;
        }

        return "en";
    }

    private void LoadAllBundles()
    {
        foreach (var lang in Languages)
        {
            try
            {
                var uri = new Uri($"avares://DNSHop.App/Assets/i18n/{lang.Culture}.json");
                using var stream = AssetLoader.Open(uri);
                using var reader = new StreamReader(stream);
                var json = reader.ReadToEnd();
                var dict = JsonSerializer.Deserialize(json, LocalizationJsonContext.Default.DictionaryStringString);
                if (dict is not null)
                {
                    _bundles[lang.Culture] = new Dictionary<string, string>(dict, StringComparer.Ordinal);
                }
            }
            catch (Exception ex)
            {
                AppDiagnostics.WriteWarning("Localization", $"Failed to load bundle for {lang.Culture}: {ex.Message}");
            }
        }
    }

    private static class Binding
    {
        public const string IndexerName = "Item[]";
    }
}

[JsonSerializable(typeof(Dictionary<string, string>))]
internal partial class LocalizationJsonContext : JsonSerializerContext
{
}
