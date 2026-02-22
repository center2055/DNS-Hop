using System;

namespace DNSHop.App.Models;

public sealed class DnsServerDefinition
{
    public required string DisplayName { get; init; }

    public required string Provider { get; init; }

    public required DnsProtocol Protocol { get; init; }

    // IP address for UDP/TCP and DoT, or host string for custom cases.
    public required string AddressOrHost { get; init; }

    public int Port { get; init; }

    public string? DohEndpoint { get; init; }

    // Hostname used for TLS SNI in DoT connections.
    public string? DotTlsHost { get; init; }

    public bool IsPinned { get; set; }

    public bool IsSidelined { get; set; }

    public string EndpointDisplay => Protocol switch
    {
        DnsProtocol.Doh => DohEndpoint ?? AddressOrHost,
        _ => $"{AddressOrHost}:{Port}",
    };

    public static DnsServerDefinition CreateUdpTcp(string ipAddress, string provider, int port = 53)
    {
        return new DnsServerDefinition
        {
            DisplayName = ipAddress,
            Provider = provider,
            Protocol = DnsProtocol.UdpTcp,
            AddressOrHost = ipAddress,
            Port = port,
        };
    }

    public static DnsServerDefinition CreateDoh(string endpoint, string provider)
    {
        var uri = new Uri(endpoint, UriKind.Absolute);

        return new DnsServerDefinition
        {
            DisplayName = uri.Host,
            Provider = provider,
            Protocol = DnsProtocol.Doh,
            AddressOrHost = uri.Host,
            Port = uri.Port,
            DohEndpoint = endpoint,
        };
    }

    public static DnsServerDefinition CreateDot(string ipOrHost, string tlsHost, string provider, int port = 853)
    {
        return new DnsServerDefinition
        {
            DisplayName = ipOrHost,
            Provider = provider,
            Protocol = DnsProtocol.Dot,
            AddressOrHost = ipOrHost,
            DotTlsHost = tlsHost,
            Port = port,
        };
    }
}

