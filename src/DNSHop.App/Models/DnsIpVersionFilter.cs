namespace DNSHop.App.Models;

/// <summary>
/// Which address families a benchmark run should cover.
/// </summary>
public enum DnsIpVersionFilter
{
    /// <summary>Test every resolver, whichever address family it uses.</summary>
    Both,

    /// <summary>Skip resolvers addressed by an IPv6 literal.</summary>
    IPv4,

    /// <summary>Test only resolvers addressed by an IPv6 literal.</summary>
    IPv6,
}
