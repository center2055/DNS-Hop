using System;

namespace DNSHop.App.Models;

public sealed class AppliedDnsEntry
{
    public required DateTimeOffset AppliedAt { get; init; }

    public required string DisplayLabel { get; init; }

    public string? PreferredIPv4 { get; init; }

    public string? AlternateIPv4 { get; init; }

    public string? PreferredIPv6 { get; init; }

    public string? AlternateIPv6 { get; init; }

    public string? ProfileId { get; init; }
}
