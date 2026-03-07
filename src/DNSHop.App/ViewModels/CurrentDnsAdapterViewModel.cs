namespace DNSHop.App.ViewModels;

public sealed class CurrentDnsAdapterViewModel
{
    public required string InterfaceName { get; init; }

    public required string Status { get; init; }

    public required string TrafficRole { get; init; }

    public required string GatewaySummary { get; init; }

    public required string Ipv4Mode { get; init; }

    public required string Ipv4Servers { get; init; }

    public required string Ipv6Mode { get; init; }

    public required string Ipv6Servers { get; init; }
}
