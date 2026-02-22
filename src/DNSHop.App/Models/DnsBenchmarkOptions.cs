namespace DNSHop.App.Models;

public sealed class DnsBenchmarkOptions
{
    // Timeout per DNS request attempt.
    public int TimeoutMilliseconds { get; init; } = 2500;

    // How many servers can be tested in parallel.
    public int ConcurrencyLimit { get; init; } = 8;

    // Attempts per probe type. Higher improves stability but increases runtime.
    public int AttemptsPerProbe { get; init; } = 1;

    // Whether to skip SSL certificate validation for DoT/DoH.
    public bool AllowInsecureSsl { get; init; } = false;

    // Optional outbound proxy for encrypted protocols (DoH/DoT).
    public DnsOutboundProxyType OutboundProxyType { get; init; } = DnsOutboundProxyType.None;

    public string OutboundProxyHost { get; init; } = string.Empty;

    public int OutboundProxyPort { get; init; } = 1080;
}
