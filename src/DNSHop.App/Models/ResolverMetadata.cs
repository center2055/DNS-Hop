namespace DNSHop.App.Models;

public sealed class ResolverMetadata
{
    public required string Key { get; init; }

    public required string Provider { get; init; }

    public string? CountryCode { get; init; }

    public string[] Regions { get; init; } = [];

    public bool NoLogs { get; init; }

    public bool BlocksMalware { get; init; }

    public bool BlocksAds { get; init; }

    public bool BlocksAdult { get; init; }

    public string? PrivacyPolicyUrl { get; init; }
}
