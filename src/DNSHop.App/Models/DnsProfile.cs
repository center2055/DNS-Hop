using System;

namespace DNSHop.App.Models;

public sealed class DnsProfile
{
    public required string Id { get; init; }

    public required string Name { get; set; }

    public string? Description { get; set; }

    public string? PreferredIPv4 { get; set; }

    public string? AlternateIPv4 { get; set; }

    public string? PreferredIPv6 { get; set; }

    public string? AlternateIPv6 { get; set; }

    public string? EncryptedEndpoint { get; set; }

    public DnsProtocol EncryptedProtocol { get; set; } = DnsProtocol.Doh;

    public bool IsBuiltIn { get; init; }

    public string? BuiltInKey { get; init; }

    public static DnsProfile CreateUserProfile(string name)
    {
        return new DnsProfile
        {
            Id = Guid.NewGuid().ToString("N"),
            Name = name,
        };
    }
}
