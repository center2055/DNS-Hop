using DNSHop.App.Models;

namespace DNSHop.App.Services;

internal sealed class AppSettings
{
    public string Theme { get; init; } = "System";

    public string Language { get; init; } = string.Empty;

    public bool UseMica { get; init; } = true;

    public string LastNavSection { get; init; } = "Home";

    public int TimeoutMilliseconds { get; init; } = 2500;

    public int ConcurrencyLimit { get; init; } = 8;

    public int AttemptsPerProbe { get; init; } = 3;

    public bool AutoUpdateListOnStartup { get; init; } = true;

    public bool CheckForAppUpdatesOnStartup { get; init; } = true;

    public string OutboundProxyType { get; init; } = "None";

    public string OutboundProxyHost { get; init; } = string.Empty;

    public int OutboundProxyPort { get; init; } = 1080;

    public DnsServerDefinition[] CustomServers { get; init; } = [];

    public string[] SidelinedServerKeys { get; init; } = [];

    public string? ActiveProfileId { get; init; }

    public DnsProfile[] Profiles { get; init; } = [];

    public AppliedDnsEntry[] ApplyHistory { get; init; } = [];
}
