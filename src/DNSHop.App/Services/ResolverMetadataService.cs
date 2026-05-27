using Avalonia.Platform;
using DNSHop.App.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DNSHop.App.Services;

internal sealed class ResolverMetadataService
{
    private Dictionary<string, ResolverMetadata> _byKey = new(StringComparer.OrdinalIgnoreCase);
    private List<ResolverMetadata> _all = new();

    public IReadOnlyList<ResolverMetadata> All => _all;

    public ResolverMetadata? Lookup(string? key)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            return null;
        }

        return _byKey.TryGetValue(key, out var value) ? value : null;
    }

    public ResolverMetadata? LookupByEndpoint(string? endpoint, string? provider)
    {
        if (!string.IsNullOrWhiteSpace(endpoint) && _byKey.TryGetValue(endpoint, out var byEndpoint))
        {
            return byEndpoint;
        }

        if (!string.IsNullOrWhiteSpace(provider) && _byKey.TryGetValue(provider, out var byProvider))
        {
            return byProvider;
        }

        return null;
    }

    public void Load()
    {
        try
        {
            var uri = new Uri("avares://DNSHop.App/Assets/resolver-metadata.json");
            using var stream = AssetLoader.Open(uri);
            using var reader = new StreamReader(stream);
            string json = reader.ReadToEnd();

            var parsed = JsonSerializer.Deserialize(json, ResolverMetadataJsonContext.Default.ListResolverMetadataDto);
            if (parsed is null)
            {
                return;
            }

            var list = new List<ResolverMetadata>(parsed.Count);
            var lookup = new Dictionary<string, ResolverMetadata>(StringComparer.OrdinalIgnoreCase);

            foreach (var item in parsed)
            {
                if (item is null || string.IsNullOrWhiteSpace(item.Key))
                {
                    continue;
                }

                var metadata = new ResolverMetadata
                {
                    Key = item.Key,
                    Provider = string.IsNullOrWhiteSpace(item.Provider) ? item.Key : item.Provider,
                    CountryCode = item.CountryCode,
                    Regions = item.Regions ?? [],
                    NoLogs = item.NoLogs,
                    BlocksMalware = item.BlocksMalware,
                    BlocksAds = item.BlocksAds,
                    BlocksAdult = item.BlocksAdult,
                    PrivacyPolicyUrl = item.PrivacyPolicyUrl,
                };

                list.Add(metadata);
                lookup[metadata.Key] = metadata;
                if (!string.IsNullOrWhiteSpace(metadata.Provider))
                {
                    lookup[metadata.Provider] = metadata;
                }
            }

            _all = list;
            _byKey = lookup;
        }
        catch (Exception ex)
        {
            AppDiagnostics.WriteWarning("ResolverMetadata", $"Failed to load metadata bundle: {ex.Message}");
        }
    }
}

internal sealed class ResolverMetadataDto
{
    public string Key { get; set; } = string.Empty;
    public string Provider { get; set; } = string.Empty;
    public string? CountryCode { get; set; }
    public string[]? Regions { get; set; }
    public bool NoLogs { get; set; }
    public bool BlocksMalware { get; set; }
    public bool BlocksAds { get; set; }
    public bool BlocksAdult { get; set; }
    public string? PrivacyPolicyUrl { get; set; }
}

[JsonSerializable(typeof(List<ResolverMetadataDto>))]
[JsonSourceGenerationOptions(PropertyNameCaseInsensitive = true)]
internal partial class ResolverMetadataJsonContext : JsonSerializerContext
{
}
